#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
command -v uv >/dev/null || {
    echo 'Install uv from https://docs.astral.sh/uv/getting-started/installation/.' >&2
    exit 1
}
uv sync --locked --python 3.12 --extra dev
uv run --locked --no-sync secops-lab demo
