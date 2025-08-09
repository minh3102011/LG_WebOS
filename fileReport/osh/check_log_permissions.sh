#!/bin/sh
echo "=== CIS 4.2.1 - Check /var/log permission ==="
perm=$(stat -c "%a" /var/log)
[ "$perm" -le 755 ] && echo "[OK] /var/log has secure permissions ($perm)" || echo "[WARN] /var/log too open ($perm)"
