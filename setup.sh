#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

python3 -m pip install --upgrade pip
python3 -m pip install "mcp>=1.0.0"

for bin in nmap curl whois; do
  if command -v "$bin" >/dev/null 2>&1; then
    echo "found binary: $bin"
  else
    echo "missing binary: $bin (install via your OS package manager)" >&2
    exit 1
  fi
done

echo "setup complete"
