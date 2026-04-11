# Contributing to Guardian

Thank you for your interest in contributing to Guardian. This document covers
everything you need: environment setup, branch naming, commit format, code style,
the PR checklist, and how to ask questions.

Guardian is licensed under [BUSL-1.1](../../LICENSE). By submitting a contribution
you agree that it may be incorporated into the project under that license.

---

## Getting Started

```bash
# 1. Clone the repository
git clone https://github.com/Viriato-Security/guardian.git
cd guardian

# 2. Create and activate a virtual environment (Python 3.12 required)
python3.12 -m venv .venv
source .venv/bin/activate

# 3. Install all dependencies
pip install -r requirements.txt

# 4. Generate proto stubs (required before first run or test)
bash scripts/gen_proto.sh

# 5. Copy the example config
cp guardian.yaml.example guardian.yaml

# 6. Run the test suite — all 63 tests must pass
python -m pytest tests/ -v
```

If any tests fail before you make changes, open an issue — that is a bug.

---

## Branch Naming

All branches must use one of the following prefixes:

| Prefix | When to use | Example |
|--------|-------------|---------|
| `feat/` | New capabilities | `feat/ebpf-loader-phase2` |
| `fix/` | Bug fixes | `fix/signer-empty-batch-crash` |
| `chore/` | Non-functional: deps, CI, tooling | `chore/update-grpcio-1.63` |
| `docs/` | Documentation only | `docs/add-proto-changes-guide` |
| `test/` | Tests only, no production code change | `test/generator-mmap-coverage` |
| `refactor/` | Restructuring without behaviour change | `refactor/enricher-lru-cache` |
| `perf/` | Performance improvements | `perf/sender-batch-drain` |

Branch names use lowercase and hyphens. No underscores, no slashes except the prefix.

---

## Conventional Commit Format

Guardian follows the [Conventional Commits](https://www.conventionalcommits.org/)
specification. Every commit message must have a type, an optional scope in
parentheses, and a short summary:

```
<type>(<scope>): <short summary in imperative mood>

[optional body — wrap at 72 characters]

[optional footer — Closes #123]
```

### Types

| Type | When to use |
|------|-------------|
| `feat` | A new feature or capability |
| `fix` | A bug fix |
| `docs` | Documentation changes only |
| `chore` | Dependency bumps, CI config, tooling, no production code |
| `test` | Adding or updating tests, no production code change |
| `refactor` | Code restructuring without behaviour change |
| `perf` | Performance improvement |

### Examples

```
feat(signer): add HMAC-SHA256 batch signing

Implements sign_batch() using hmac.new(token, payload, sha256).
Payload is a JSON array of {prev, this} hash pairs, one per event.

Closes #12
```

```
fix(generator): correct nanosecond timestamp padding

datetime.microsecond gives 6 digits. Pad with 3 trailing zeros to
produce the 9-digit nanosecond field required by the proto schema.
```

```
chore(deps): bump grpcio to 1.63.0
```

```
docs(readme): add Event schema table with proto field numbers
```

```
test(local_alerts): add coverage for sendto-based unexpected_network
```

```
refactor(enricher): replace manual LRU with functools.lru_cache

No behaviour change. Removes 30 lines of manual dict management.
```

```
perf(sender): drain buffer in reverse order to avoid repeated file rewrites
```

### Rules

- Use imperative mood in the summary: "add", "fix", "update", not "added", "fixed".
- Keep the summary line under 72 characters.
- Do not end the summary with a period.
- The body is optional but encouraged for non-trivial changes.

---

## Pull Request Checklist

Before opening a PR, verify every item:

- [ ] All tests pass: `python -m pytest tests/ -v`
- [ ] `python -m mypy agent/ --strict --python-version=3.12 --ignore-missing-imports` passes with no errors
- [ ] All public functions and methods have type hints
- [ ] All new classes and public methods have docstrings
- [ ] `guardian.yaml` is **not** staged or committed (it is in `.gitignore`)
- [ ] Generated proto stubs (`proto/guardian_pb2.py`, `proto/guardian_pb2_grpc.py`) are **not** committed
- [ ] `pending.jsonl` (disk buffer) is **not** committed
- [ ] No new dependencies added without prior discussion in a GitHub issue
- [ ] If a new event field was added: `RawEvent`, `guardian.proto`, `README.md` schema table, and `sender._build_batch_proto()` are all updated
- [ ] If a new alert type was added: `guardian.yaml.example` updated, tests cover fires/no-fires/custom-handler cases

---

## Code Style

Guardian targets Python 3.12+.

### Formatting and structure

- Every module begins with `from __future__ import annotations` (enables PEP 563 postponed evaluation).
- Lines must be under **100 characters** wide.
- Use the **standard library** wherever possible. New runtime dependencies require
  a discussion issue before being added.
- Prefer **explicit over implicit**: no magic, no metaprogramming, no clever one-liners
  that sacrifice readability.

### Type hints

All public function signatures and method signatures must be fully typed, including
return types. Use `Optional[T]` for nullable parameters (not `T | None` for Python 3.9
compatibility).

```python
# Correct
def enrich(self, event: RawEvent) -> RawEvent:
    ...

# Incorrect — missing return type
def enrich(self, event: RawEvent):
    ...
```

### Docstrings

Every new class and every public method needs a docstring. Follow the Google style:

```python
def sign_batch(self, events: list[RawEvent]) -> str:
    """Return an HMAC-SHA256 hex signature over the hashes of *events*.

    Args:
        events: Non-empty list of already-chained events.

    Returns:
        64-character lowercase hex string.

    Raises:
        ValueError: If *events* is empty.
    """
```

### Module-level constants

Use `UPPER_SNAKE_CASE` for module-level constants. Prefix internal constants with
a leading underscore:

```python
_MAX_BUFFER_LINES = 10_000
GENESIS_HASH = "0" * 64
```

### Error handling

Raise the most specific built-in exception type (`ValueError`, `FileNotFoundError`,
`NotImplementedError`). Do not catch broad `Exception` in library code; only in
top-level entry points with logging.

---

## Adding a New Module

If your feature requires a new file in `agent/`:

1. The module must have a module-level docstring explaining its purpose.
2. All public classes and functions need type hints and docstrings.
3. Add corresponding tests in `tests/test_<module_name>.py`.
4. Import the module in `agent/__init__.py` only if it needs to be part of the
   public API; internal helpers do not need to be re-exported.

---

## Running a Single Test

```bash
# Run a single test function
python -m pytest tests/test_local_alerts.py::test_sandbox_escape_fires_on_bin_bash -v

# Run all tests in a file
python -m pytest tests/test_generator.py -v

# Run tests matching a keyword
python -m pytest tests/ -v -k "signer"
```

---

## Questions?

- Open a [GitHub issue](https://github.com/Viriato-Security/guardian/issues) for
  bugs, feature requests, or design discussions.
- Email [hello@viriatosecurity.com](mailto:hello@viriatosecurity.com) for security
  disclosures or commercial enquiries.
- See [SECURITY.md](../../SECURITY.md) for the vulnerability disclosure policy.

---

## Related Documents

- [local-setup.md](local-setup.md)
- [adding-a-syscall.md](adding-a-syscall.md)
- [adding-an-alert.md](adding-an-alert.md)
- [proto-changes.md](proto-changes.md)
- [../../CONTRIBUTING.md](../../CONTRIBUTING.md)
