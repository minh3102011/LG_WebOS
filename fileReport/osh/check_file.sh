#!/bin/sh
echo "=== Checking for insecure dotfiles (.rhosts, .netrc, .forward) in user homes ==="

dotfiles=".rhosts .netrc .forward"

for dir in /home/* /root; do
    for file in $dotfiles; do
        if [ -e "$dir/$file" ]; then
            echo "[WARN] Found $file in $dir"
        fi
    done
done
echo "[OK] Dotfile scan complete"

