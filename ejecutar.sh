#!/bin/sh
# Linux: la captura necesita privilegios de root.
cd "$(dirname "$0")"
sudo python3 main.py "$@"
