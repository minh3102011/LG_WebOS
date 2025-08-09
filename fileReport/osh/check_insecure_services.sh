#!/bin/sh
echo "=== CIS 2.1.x - Check for insecure services ==="

for srv in telnet ftp tftp rsh rlogin ypbind ypserv talk; do
    ps aux | grep "$srv" | grep -v grep > /dev/null
    if [ $? -eq 0 ]; then
        echo "[WARN] $srv is running"
    else
        echo "[OK] $srv not running"
    fi
done