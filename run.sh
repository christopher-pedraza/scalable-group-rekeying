#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# TODO: decide if we will plot with matplotlib. If so:
# uv add --group plots matplotlib
uv sync --locked --group plots
uv run python demo.py "$@"