#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

uv sync --locked
uv run python demo.py "$@"