#!/bin/sh
echo "=== Checking for Dropbear SSH login events in syslog/messages ==="

LOGFILES="/var/log/messages /var/log/syslog /var/log/auth.log"

found=0

for log in $LOGFILES; do
    if [ -f "$log" ]; then
        echo "--- Checking $log ---"
        grep -Ei "dropbear.*(login|auth|session)" "$log" && found=1
    fi
done

if [ $found -eq 0 ]; then
    echo "[INFO] No Dropbear login entries found in available logs"
fi
