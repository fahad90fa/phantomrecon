# Contributing to PhantomRecon

Thank you for helping build PhantomRecon. Follow these guidelines to keep the project high-quality and aligned with the existing architecture.

## Code Contributions
1. **Branch strategy**: Create a feature branch per logical change (e.g., `feat/hydra-tuning`, `fix/deserialization-escape`). Keep commits focused and rebase on `main` before merging.
2. **Code style**: Keep files Pythonic — use type hints, f-strings, dataclasses, and enum members already present in the modules. Follow the existing conventions in `modules/` (grouped imports, descriptive docstrings, and minimal inline comments).
3. **New dependencies**: Add any new third-party packages to `requirements.txt` only when absolutely necessary, and explain the use case in the pull request description.
4. **Tests**: Add or extend `tests/` whenever you touch functionality. Run `python -m pytest tests` locally before pushing.
5. **Formatting**: Run `python -m black .` (or `ruff check` if configured) to keep formatting consistent.

## Issue Reporting
- Search open issues before filing a new one; include steps to reproduce, CLI/GUI context, and relevant logs (JSON output from `tests/`, `phantomrecon_http_*.json`, etc.).
- Label issues clearly (e.g., `bug`, `enhancement`, `module:hydra`).

## Pull Requests
- Link to the issue your PR addresses and summarize the impact (modules touched, commands affected).
- Highlight any breaking changes or required manual steps (e.g., regenerating the GUI binary or updating `requirements.txt`).
- Keep PR descriptions actionable with testing notes (commands run and test coverage).

## Communication
- Use GitHub Discussions or Issues for architectural proposals before implementing large features.
- For urgent security fixes, open an issue with the `security` label and mention that the change will land quickly after verification.
