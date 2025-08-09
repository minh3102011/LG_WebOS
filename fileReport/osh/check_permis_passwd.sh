#!/bin/sh
echo "=== Checking file permissions of /etc/passwd and /etc/shadow ==="

check_permission() {
    file=$1
    expected_perm=$2
    perm=$(stat -c "%a" $file 2>/dev/null)

    if [ "$perm" = "$expected_perm" ]; then
        echo "[OK] $file has correct permission $perm"
    else
        echo "[WARN] $file has permission $perm, expected $expected_perm"
    fi
}

check_permission /etc/passwd 644
check_permission /etc/shadow 600

