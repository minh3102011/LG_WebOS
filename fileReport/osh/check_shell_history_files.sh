#!/bin/sh
echo "=== CIS 5.4.4 - Check for shell history files ==="
find /root /home -name ".*history" 2>/dev/null && echo "[WARN] Shell history files exist" || echo "[OK] No history files"
