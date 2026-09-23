#!/bin/bash
# One-command starter for the AI Search Visibility Agent.
# Usage:  ./start.sh [--port 8000]
# Needs:  agent.py + index.html in this same folder.
set -e
cd "$(dirname "$0")"
PORT=8000
if [ "$1" = "--port" ] && [ -n "$2" ]; then PORT="$2"; fi

PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then echo "ERROR: install Python 3.10+ first (https://www.python.org/downloads/)"; exit 1; fi
echo "Using: $PY ($($PY --version 2>&1))"

echo "Installing packages (requests, LLMs)..."
$PY -m pip install --quiet --disable-pip-version-check requests google-generativeai groq 2>&1 | tail -2 || {
  echo "WARNING: pip install had issues - continuing anyway (agent runs with reduced features)."
}

echo "Starting agent on port $PORT ..."
echo "Open:  http://<this-server-ip>:$PORT   (login: admin / changeme123)"
echo "First boot takes ~1 minute (creates database)."
PORT="$PORT" $PY agent.py --port "$PORT"
