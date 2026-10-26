#!/bin/sh
cd "$(dirname "$0")"
echo "Starting TRACE on http://127.0.0.1:8765"
( sleep 1; command -v xdg-open >/dev/null && xdg-open http://127.0.0.1:8765/ ) &
exec python3 backend.py "$@"
