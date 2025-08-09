#!/bin/sh
echo "=== CIS 3.1 - Check default umask in init scripts ==="
grep -r umask /etc/init.d 2>/dev/null | grep -v '#' && echo "[OK] umask configured" || echo "[WARN] No umask set for daemons"
