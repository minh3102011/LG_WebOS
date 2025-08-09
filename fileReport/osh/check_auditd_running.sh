#!/bin/sh
echo "=== CIS 4.1.1 - Check if auditd service is running ==="
pgrep auditd > /dev/null && echo "[OK] auditd is running" || echo "[WARN] auditd is not running"
