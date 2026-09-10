# CLAUDE.md

See [AGENTS.md](AGENTS.md) — one source of truth for how work is done in this repository.

Short version: run `make check` before every commit, write the test first, and keep the
architectural contracts in `pyproject.toml` intact. This service holds other people's
credentials; the security invariants in AGENTS.md are not negotiable.
