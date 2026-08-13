#!/usr/bin/env python3
"""Test real UDisks2 attack surface"""
import dbus
import os

print(f"uid={os.getuid()}")
bus = dbus.SystemBus()

# Test 1: Enumerate all block devices
print("\n=== Test 1: UDisks2 GetBlockDevices ===")
mgr = bus.get_object('org.freedesktop.UDisks2', '/org/freedesktop/UDisks2/Manager')
mgr_iface = dbus.Interface(mgr, 'org.freedesktop.UDisks2.Manager')
try:
    devs = mgr_iface.GetBlockDevices(dbus.Dictionary({}, signature='sv'))
    print(f"  Found {len(devs)} block devices:")
    for d in devs:
        print(f"    {d}")
except Exception as e:
    print(f"  Result: {e}")

# Test 2: Read properties of each block device
print("\n=== Test 2: Block device properties ===")
for dev_path in ['/org/freedesktop/UDisks2/block_devices/vda',
                 '/org/freedesktop/UDisks2/block_devices/vda1']:
    try:
        dev = bus.get_object('org.freedesktop.UDisks2', dev_path)
        props = dbus.Interface(dev, 'org.freedesktop.DBus.Properties')
        block_props = props.GetAll('org.freedesktop.UDisks2.Block')
        dev_bytes = bytes(block_props.get('Device', b''))
        size = block_props.get('Size', 0)
        id_type = str(block_props.get('IdType', ''))
        id_label = str(block_props.get('IdLabel', ''))
        print(f"  {dev_path}:")
        print(f"    Device={dev_bytes}, Size={size}, IdType={id_type}, IdLabel={id_label}")
    except Exception as e:
        print(f"  {dev_path}: {e}")

# Test 3: Try to mount
print("\n=== Test 3: UDisks2 Filesystem.Mount (vda1) ===")
try:
    vda1 = bus.get_object('org.freedesktop.UDisks2', '/org/freedesktop/UDisks2/block_devices/vda1')
    fs_iface = dbus.Interface(vda1, 'org.freedesktop.UDisks2.Filesystem')
    mount_point = fs_iface.Mount(dbus.Dictionary({}, signature='sv'))
    print(f"  SUCCESS: mounted at {mount_point}")
except Exception as e:
    print(f"  Result: {e}")

# Test 4: Try LoopSetup
print("\n=== Test 4: UDisks2 LoopSetup ===")
try:
    with open('/tmp/test.img', 'wb') as f:
        f.write(b'\x00' * 1048576)
    fd = os.open('/tmp/test.img', os.O_RDONLY)
    loop = mgr_iface.LoopSetup(dbus.types.UnixFd(fd), dbus.Dictionary({}, signature='sv'))
    print(f"  SUCCESS: loop device at {loop}")
    os.close(fd)
except Exception as e:
    print(f"  Result: {e}")

# Test 5: Read drive info
print("\n=== Test 5: UDisks2 Drive info ===")
try:
    drives_obj = bus.get_object('org.freedesktop.UDisks2', '/org/freedesktop/UDisks2/drives')
    intro = dbus.Interface(drives_obj, 'org.freedesktop.DBus.Introspectable')
    xml = intro.Introspect()
    import re
    drive_names = re.findall(r'node name="([^"]+)"', xml)
    for dn in drive_names:
        drive = bus.get_object('org.freedesktop.UDisks2', f'/org/freedesktop/UDisks2/drives/{dn}')
        dp = dbus.Interface(drive, 'org.freedesktop.DBus.Properties')
        drive_props = dp.GetAll('org.freedesktop.UDisks2.Drive')
        model = str(drive_props.get('Model', ''))
        serial = str(drive_props.get('Serial', ''))
        size = drive_props.get('Size', 0)
        print(f"  {dn}: Model={model}, Serial={serial}, Size={size}")
except Exception as e:
    print(f"  Result: {e}")
