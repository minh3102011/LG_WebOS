#!/bin/sh
echo "=== CIS 5.5.1 - Check for users with empty passwords ==="
awk -F: '($2 == "") {print "[WARN] Empty password for:", $1}' /etc/shadow || echo "[OK] No empty passwords"
