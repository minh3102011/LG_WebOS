#!/bin/sh
echo "=== Checking for system users with login shells ==="

flag=0
while IFS=: read -r user _ _ _ _ _ shell; do
    if echo "$shell" | grep -vqE "(nologin|false)"; then
        case "$user" in
            root) continue ;; # Skip root
            *) echo "[WARN] User $user has shell $shell"; flag=1 ;;
        esac
    fi
done < /etc/passwd

if [ $flag -eq 0 ]; then
    echo "[OK] All system users have non-login shell"
fi

