# Contributing to Guardian

Thank you for your interest in contributing to Guardian!

Guardian is open for external contributions under [BUSL-1.1](LICENSE).
By contributing you agree that your contributions may be incorporated into
the project under that license.

---

## Getting Started

```bash
git clone https://github.com/Viriato-Security/guardian.git
cd guardian
pip install -r requirements.txt
bash scripts/gen_proto.sh
cp guardian.yaml.example guardian.yaml
python -m pytest tests/ -v   # all tests must pass
```

---

## Branch Naming

| Prefix | When to use |
|--------|-------------|
| `feat/` | New features (e.g. `feat/ebpf-loader-phase2`) |
| `fix/`  | Bug fixes (e.g. `fix/signer-empty-batch`) |
| `chore/` | Non-functional changes — deps, CI, docs (e.g. `chore/update-grpcio`) |

---

## Commit Message Format

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <short summary>

[optional body]

[optional footer — closes #issue]
```

Examples:
```
feat(signer): add HMAC-SHA256 batch signing

fix(generator): correct nanosecond timestamp format

chore(deps): bump grpcio to 1.63.0
```

Types: `feat`, `fix`, `docs`, `chore`, `test`, `refactor`, `perf`

---

## Pull Request Checklist

Before opening a PR, verify:

- [ ] All tests pass: `python -m pytest tests/ -v`
- [ ] New code has type hints on all public functions and methods
- [ ] New classes and public methods have docstrings
- [ ] `guardian.yaml` is **not** committed (it is in `.gitignore`)
- [ ] Generated proto stubs (`proto/*_pb2*.py`) are **not** committed
- [ ] No new dependencies added without discussion in an issue first
- [ ] If adding a new event field, update all of: `RawEvent`, `guardian.proto`, `README.md` schema table

---

## Code Style

- Python 3.12+, standard library preferred
- `from __future__ import annotations` at the top of every module
- No external linter required, but keep lines under 100 characters
- Prefer explicit over implicit; no magic

---

## Questions?

Open an issue or email [hello@viriatosecurity.com](mailto:hello@viriatosecurity.com).
