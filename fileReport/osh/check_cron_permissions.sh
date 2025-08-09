#!/bin/sh
echo "=== CIS 5.1.2 - Check cron file permissions ==="
flag=0
for f in /etc/crontab /etc/cron.*; do
    [ -e "$f" ] && {
        perm=$(stat -c "%a" "$f")
        echo "[INFO] $f permission: $perm"
        flag=1
    }
done
[ $flag -eq 0 ] && echo "[OK] No cron files found or all permissions safe"
