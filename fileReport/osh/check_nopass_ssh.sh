#!/bin/sh
echo "=== Dropbear Password Login Check ==="

# Find dropbear processes
dropbear_cmd=$(ps aux | grep '[d]ropbear' | awk '{for (i=11; i<=NF; i++) printf "%s ", $i; print ""}')

if echo "$dropbear_cmd" | grep -q -- "-s"; then
    echo "[OK] Dropbear is running with -s (password login is disabled)"
else
    echo "[WARN] Dropbear is NOT running with -s (password login might be allowed)"
fi

# Optional: check public key login files for root and other users
for user in root pdmuser; do
    auth_keys="/home/$user/.ssh/authorized_keys"
    [ -f "$auth_keys" ] || auth_keys="/$user/.ssh/authorized_keys"
    
    if [ -f "$auth_keys" ]; then
        echo "[OK] Public key found for $user at $auth_keys"
    else
        echo "[WARN] No authorized_keys file found for $user"
    fi
done
