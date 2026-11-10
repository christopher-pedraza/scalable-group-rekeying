# scalable-group-rekeying

## Development setup

```bash
uv sync                        # install dependencies
uv run pre-commit install      # auto-format and lint on every commit
```

The hook keeps formatting consistent across contributors, so CI doesn't fail on style.

Before pushing, you can run the same checks as CI:

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest
```
