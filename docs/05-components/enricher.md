# Enricher (`agent/enricher.py`)

## Overview

The `Enricher` class populates context fields on each `RawEvent` before the event reaches the `Signer`. These fields — `agent_id`, `model_name`, `container_id`, `pod_name`, `namespace` — are not available from the kernel at the time of the syscall; they must be resolved from the host environment, configuration, and persistent state.

Enrichment happens **before signing**. This is a deliberate and critical ordering: the SHA-256 hash of each event (its `this_hash`) is computed over all event fields, including the enriched fields. If enrichment happened after signing, the context fields would not be part of the cryptographic commitment and could be altered without detection.

---

## Why Enrichment Happens Before Signing

The `_hash_event()` function in `agent/signer.py` serialises all fields of `RawEvent` except `this_hash` itself. This means `agent_id`, `model_name`, `container_id`, `pod_name`, and `namespace` are all included in the hash input.

If an attacker could alter `model_name` after signing (e.g. to change which model is attributed with a sandbox escape), the hash would remain valid but the attribution would be wrong. By enriching before signing, the context fields are locked into the hash.

The pipeline order in `agent/main.py` is:

```
generator → enricher → signer → local_alerts → sender
```

---

## `Enricher` Class

```python
class Enricher:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._agent_id: str = _load_or_create_agent_id()
        self._pod_name: str = os.environ.get("KUBERNETES_POD_NAME", "")
        self._namespace: str = os.environ.get("KUBERNETES_NAMESPACE", "")
```

The Enricher is constructed once per agent run. `_load_or_create_agent_id()` is called at construction time and the result is cached in `self._agent_id`. Similarly, `pod_name` and `namespace` are read from environment variables once and cached — these do not change during a container's lifetime.

### `enrich(event: RawEvent) -> RawEvent`

```python
def enrich(self, event: RawEvent) -> RawEvent:
    event.agent_id = self._agent_id
    event.model_name = self._config.model_name_for_process(event.process)
    event.container_id = self._container_id(event.pid)
    event.pod_name = self._pod_name
    event.namespace = self._namespace
    return event
```

Mutates `event` in-place and returns the same object (for pipeline chaining convenience). All five enriched fields are set unconditionally; if a field has no value (e.g. not in a container), it is set to an empty string `""`.

---

## `agent_id` Persistence

The `agent_id` is a UUID4 that uniquely identifies a Guardian installation. It is used in `AlertEvent`, in the `EventBatch` proto, and as a key on the Viriato control plane to associate events with a specific host or pod.

### Lookup and Creation Logic

```python
_AGENT_ID_PROD = "/var/lib/guardian/.agent_id"
_AGENT_ID_DEV  = os.path.expanduser("~/.guardian_agent_id")

def _load_or_create_agent_id() -> str:
    for path in (_AGENT_ID_PROD, _AGENT_ID_DEV):
        if os.path.isfile(path):
            try:
                agent_id = open(path).read().strip()
                uuid.UUID(agent_id)  # validate format
                return agent_id
            except (OSError, ValueError):
                pass

    new_id = str(uuid.uuid4())
    for path in (_AGENT_ID_PROD, _AGENT_ID_DEV):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(new_id)
            logger.info("Created agent_id %s at %s", new_id, path)
            return new_id
        except OSError:
            continue

    logger.warning("Could not persist agent_id — using ephemeral UUID")
    return new_id
```

**Step 1: Read production path.** Try to read `/var/lib/guardian/.agent_id`. If the file exists and its contents parse as a valid UUID4 (`uuid.UUID(agent_id)` does not raise `ValueError`), return it.

**Step 2: Read development path.** If the production path is absent or invalid, try `~/.guardian_agent_id`.

**Step 3: Create and persist.** If neither file exists, generate a new UUID4 and try to write it to the production path first. If that fails with `OSError` (typically `PermissionError`), try the development path.

**Step 4: Ephemeral fallback.** If both write attempts fail, log a warning and return the UUID as an in-memory-only value. The agent will use a different `agent_id` on the next restart, breaking continuity on the control plane.

### UUID Validation on Read

The line `uuid.UUID(agent_id)` validates the format of the stored value. This catches:
- Files that were accidentally overwritten with non-UUID content.
- Truncated writes from a previous crash.
- Version mismatches (e.g. a non-v4 UUID from a different tool).

If validation fails, the file is ignored and the lookup proceeds to the next path, eventually creating a new UUID.

### Two-Path Design Rationale

| Path | Use case |
|---|---|
| `/var/lib/guardian/.agent_id` | Production: Guardian runs as a service with write access to `/var/lib/guardian/`. |
| `~/.guardian_agent_id` | Development: Guardian runs as a regular user. The home directory is always writable. |

In Kubernetes, the production path should be on a persistent volume so that pod restarts preserve the `agent_id`. If the pod uses an ephemeral container filesystem, each restart generates a new `agent_id` and the control plane sees a new installation.

---

## `model_name` Resolution

```python
event.model_name = self._config.model_name_for_process(event.process)
```

Delegates to `Config.model_name_for_process()`, which iterates the `watch` list and returns the first matching model name, or `"unknown"` if the process is not configured.

This means events from unrecognised processes (e.g. system daemons) will have `model_name = "unknown"`. The control plane can filter or group these separately.

---

## `container_id` Lookup

```python
@functools.lru_cache(maxsize=512)
def _container_id(self, pid: int) -> str:
    cgroup_path = f"/proc/{pid}/cgroup"
    try:
        with open(cgroup_path) as fh:
            content = fh.read()
    except OSError:
        return ""

    match = _DOCKER_CGROUP_RE.search(content)
    if match:
        return match.group(1)[:12]
    return ""
```

### How Container ID Detection Works

On a host running Docker containers, the kernel writes each container's cgroup hierarchy into `/proc/<pid>/cgroup`. A typical entry looks like:

```
12:devices:/docker/a1b2c3d4e5f6g7h8i9j0a1b2c3d4e5f6g7h8i9j0a1b2c3d4e5f6
```

The regex `r"/docker/([a-f0-9]{12,64})"` extracts the hexadecimal container ID (between 12 and 64 characters). The first 12 characters are returned as the "short container ID" — the same format used by `docker ps`.

**Returns:**
- A 12-character lowercase hexadecimal string (e.g. `"a1b2c3d4e5f6"`) if the process is in a Docker container.
- `""` (empty string) if the process is not in a container, if `/proc/<pid>/cgroup` does not exist (process exited), or on any `OSError`.

### LRU Cache

`_container_id()` is decorated with `@functools.lru_cache(maxsize=512)`. The cache key is the `pid` integer.

This optimisation avoids reading `/proc/<pid>/cgroup` on every event for the same PID. In a typical workload where a small number of long-running inference processes generate thousands of events, the cache hit rate is very high.

**Cache size 512:** Supports monitoring up to 512 distinct PIDs simultaneously without eviction. If a deployment has more than 512 concurrent monitored PIDs, the LRU eviction will cause `/proc` reads for re-encountered PIDs, which is a performance degradation but not a correctness issue.

**Stale cache concern:** If a container is restarted with the same PID (possible in short-lived container workloads), the cached container ID might be from the previous container. This is a known Phase 1 limitation; Phase 2 will use cgroup namespace IDs directly from the eBPF perf event.

---

## `pod_name` and `namespace` from Kubernetes Downward API

```python
self._pod_name: str = os.environ.get("KUBERNETES_POD_NAME", "")
self._namespace: str = os.environ.get("KUBERNETES_NAMESPACE", "")
```

These values come from Kubernetes Downward API environment variable injection. The Kubernetes manifest must include:

```yaml
env:
  - name: KUBERNETES_POD_NAME
    valueFrom:
      fieldRef:
        fieldPath: metadata.name
  - name: KUBERNETES_NAMESPACE
    valueFrom:
      fieldRef:
        fieldPath: metadata.namespace
```

If these environment variables are absent (non-Kubernetes deployment), both fields are set to `""`. This is not an error; the control plane treats empty strings as "not applicable."

The values are read once at `Enricher` construction time and cached. Kubernetes does not change pod name or namespace during a pod's lifetime.

---

## Performance Characteristics

| Operation | Cost | Caching |
|---|---|---|
| `agent_id` lookup | One-time file read at startup | Permanent (stored in `self._agent_id`) |
| `model_name` lookup | O(n) linear scan of `watch` list | None (fast enough for small lists) |
| `container_id` lookup | One `/proc/<pid>/cgroup` file read | LRU cache, 512 slots |
| `pod_name` lookup | One `os.environ.get()` at startup | Permanent (stored in `self._pod_name`) |
| `namespace` lookup | One `os.environ.get()` at startup | Permanent (stored in `self._namespace`) |

On a typical deployment with 5–10 watch entries, `enrich()` performs at most one `/proc` read (on a cache miss) and a short linear scan of the watch list. The hot path for already-seen PIDs is entirely in-memory.

---

## `agent_id` Property

```python
@property
def agent_id(self) -> str:
    """The UUID identifying this Guardian installation."""
    return self._agent_id
```

Exposed as a read-only property so that `Sender` and the pipeline setup code can read the `agent_id` from the `Enricher` without re-loading it from disk.

---

## Related Documents

- `docs/04-security/event-chaining.md` — why enriched fields must be included in the hash
- `docs/04-security/cryptographic-design.md` — enrichment-before-signing ordering
- `docs/05-components/config-loader.md` — `WatchEntry`, `model_name_for_process()`
- `docs/05-components/signer.md` — receives enriched events, computes `this_hash` including all enriched fields
- `docs/05-components/sender.md` — reads `agent_id` from the `Enricher` at pipeline setup
