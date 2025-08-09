#!/bin/sh
echo "=== CIS 5.4.1.3 - Check for duplicate UIDs ==="

dups=$(cut -d: -f3 /etc/passwd | sort | uniq -d)

if [ -n "$dups" ]; then
    for uid in $dups; do
        grep ":$uid:" /etc/passwd | awk -F: '{print "[WARN] Duplicate UID:", $1, "(UID:", $3 ")"}'
    done
else
    echo "[OK] No duplicate UIDs"
fi
