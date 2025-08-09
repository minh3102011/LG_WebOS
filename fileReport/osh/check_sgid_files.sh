#!/bin/sh
echo "=== CIS 1.1.3 - Find SGID files ==="
find / -perm -2000 -type f 2>/dev/null | grep -vE '^/proc|^/sys|^/dev' && echo "[WARN] SGID files exist" || echo "[OK] No SGID files"
