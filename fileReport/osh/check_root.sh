#!/bin/sh
echo "=== Checking if root account is locked ==="

passwd_status=$(grep "^root:" /etc/shadow | cut -d: -f2)

if echo "$passwd_status" | grep -q '^!'; then
    echo "[OK] Root account is locked"
else
    echo "[WARN] Root account is not locked"
fi

