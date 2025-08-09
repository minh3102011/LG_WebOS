#!/bin/sh
echo "=== CIS 4.1.2 - Ensure audit rules exist ==="
[ -s /etc/audit/audit.rules ] && echo "[OK] Audit rules are present" || echo "[WARN] No audit rules found"
