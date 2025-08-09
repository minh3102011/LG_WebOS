#!/bin/sh
echo "=== CIS 5.4.1.4 - Check for duplicate GIDs ==="

dups=$(cut -d: -f3 /etc/group | sort | uniq -d)

if [ -n "$dups" ]; then
    for gid in $dups; do
        grep ":$gid:" /etc/group | awk -F: '{print "[WARN] Duplicate GID:", $1, "(GID:", $3 ")"}'
    done
else
    echo "[OK] No duplicate GIDs"
fi
