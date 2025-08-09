#!/bin/sh
echo "=== CIS 1.1.2 - Find SUID files ==="
find / -perm -4000 -type f 2>/dev/null | grep -vE '^/proc|^/sys|^/dev' && echo "[WARN] SUID files exist" || echo "[OK] No SUID files"
