#!/usr/bin/env python3
"""
NA6-NA16 综合漏洞服务
模拟 UDisks2, PackageKit, wpa_supplicant, NM Settings, Firewall1 等
用于验证 PATH/MEMBER/INTERFACE/DESTINATION 各字段的攻击场景
"""
import dbus, dbus.service, dbus.mainloop.glib
from gi.repository import GLib
import os, logging, json

logging.basicConfig(level=logging.INFO, format='[NA-Services] %(asctime)s %(levelname)s: %(message)s')
log = logging.getLogger('NA')

# ============================================================
# NA6 + NA8: 模拟 UDisks2 (PATH 选择设备 + MEMBER=Format)
# ============================================================
class FakeUDisks2Manager(dbus.service.Object):
    def __init__(self, bus):
        super().__init__(bus, '/org/freedesktop/UDisks2/Manager')
        self._format_count = 0
        log.info("[UDisks2] Manager registered at /org/freedesktop/UDisks2/Manager")

class FakeUDisks2Block(dbus.service.Object):
    def __init__(self, bus, device_name):
        self._path = f'/org/freedesktop/UDisks2/block_devices/{device_name}'
        super().__init__(bus, self._path)
        self._device = device_name
        self._format_count = 0
        log.info("[UDisks2] Block device registered: %s", self._path)

    @dbus.service.method('org.freedesktop.UDisks2.Block', in_signature='sa{sv}', out_signature='s')
    def Format(self, fs_type, options):
        self._format_count += 1
        log.warning("=" * 60)
        log.warning("[UDisks2] Format() called on %s (#%d)", self._path, self._format_count)
        log.warning("  device=%s, fs_type=%s", self._device, fs_type)
        log.warning("  options=%s", dict(options) if options else "{}")
        log.warning("  UID=%d (0=root)", os.getuid())
        if self._device == "sda":
            log.warning("  !!! SYSTEM DISK /dev/sda — DESTRUCTIVE !!!")
        log.warning("  ATTACK: unprivileged user formatting /dev/%s as root", self._device)
        log.warning("=" * 60)
        with open('/tmp/udisks2_format_log.txt', 'a') as f:
            f.write(f"Format #{self._format_count}: /dev/{self._device} fs={fs_type}\n")
        return f"FORMATTED /dev/{self._device} as {fs_type}"

    @dbus.service.method('org.freedesktop.UDisks2.Filesystem', in_signature='a{sv}', out_signature='s')
    def Mount(self, options):
        log.warning("[UDisks2] Mount() on %s — privileged mount as root!", self._path)
        with open('/tmp/udisks2_mount_log.txt', 'a') as f:
            f.write(f"Mount: /dev/{self._device}\n")
        return f"/media/root/{self._device}"

# ============================================================
# NA7: 模拟 NetworkManager Settings (PATH 选择连接 → GetSecrets)
# ============================================================
class FakeNMConnection(dbus.service.Object):
    def __init__(self, bus, conn_id, secrets):
        self._path = f'/org/freedesktop/NetworkManager/Settings/{conn_id}'
        super().__init__(bus, self._path)
        self._conn_id = conn_id
        self._secrets = secrets
        log.info("[NM] Connection registered: %s", self._path)

    @dbus.service.method('org.freedesktop.NetworkManager.Settings.Connection',
                         in_signature='s', out_signature='a{sa{sv}}')
    def GetSecrets(self, setting_name):
        log.warning("=" * 60)
        log.warning("[NM] GetSecrets('%s') on %s", setting_name, self._path)
        log.warning("  Returning secrets: %s", list(self._secrets.keys()))
        log.warning("  ATTACK: PATH controls which connection's secrets are leaked!")
        log.warning("=" * 60)
        result = {}
        for k, v in self._secrets.items():
            result[k] = dbus.Dictionary({
                'password': dbus.String(v, variant_level=1)
            }, signature='sv')
        with open('/tmp/nm_secrets_log.txt', 'a') as f:
            f.write(f"GetSecrets on {self._path}: {json.dumps(self._secrets)}\n")
        return dbus.Dictionary(result, signature='sa{sv}')

# ============================================================
# NA9: 模拟 PackageKit (MEMBER=InstallPackages)
# ============================================================
class FakePackageKit(dbus.service.Object):
    def __init__(self, bus):
        super().__init__(bus, '/org/freedesktop/PackageKit')
        self._install_count = 0
        log.info("[PackageKit] registered at /org/freedesktop/PackageKit")

    @dbus.service.method('org.freedesktop.PackageKit', in_signature='', out_signature='o')
    def CreateTransaction(self):
        log.info("[PackageKit] CreateTransaction()")
        return dbus.ObjectPath('/org/freedesktop/PackageKit/Transactions/1')

class FakePackageKitTransaction(dbus.service.Object):
    def __init__(self, bus):
        super().__init__(bus, '/org/freedesktop/PackageKit/Transactions/1')
        self._install_count = 0
        log.info("[PackageKit] Transaction registered")

    @dbus.service.method('org.freedesktop.PackageKit.Transaction',
                         in_signature='tas', out_signature='s')
    def InstallPackages(self, flags, package_ids):
        self._install_count += 1
        pkgs = list(package_ids)
        log.warning("=" * 60)
        log.warning("[PackageKit] InstallPackages() (#%d)", self._install_count)
        log.warning("  packages=%s", pkgs)
        log.warning("  UID=%d (0=root) — installing as root!", os.getuid())
        log.warning("  ATTACK: MEMBER=InstallPackages triggers root pkg install")
        log.warning("=" * 60)
        with open('/tmp/packagekit_install_log.txt', 'a') as f:
            f.write(f"Install #{self._install_count}: {pkgs}\n")
        return f"INSTALLED {pkgs} as root"

# ============================================================
# NA10: 模拟 wpa_supplicant (MEMBER=AddNetwork)
# ============================================================
class FakeWpaSupplicant(dbus.service.Object):
    def __init__(self, bus):
        super().__init__(bus, '/fi/w1/wpa_supplicant1/Interfaces/0')
        self._net_count = 0
        log.info("[wpa_supplicant] registered at /fi/w1/wpa_supplicant1/Interfaces/0")

    @dbus.service.method('fi.w1.wpa_supplicant1.Interface',
                         in_signature='a{sv}', out_signature='o')
    def AddNetwork(self, config):
        self._net_count += 1
        cfg = {str(k): str(v) for k, v in config.items()}
        log.warning("=" * 60)
        log.warning("[wpa_supplicant] AddNetwork() (#%d)", self._net_count)
        log.warning("  config=%s", cfg)
        log.warning("  UID=%d (0=root)", os.getuid())
        log.warning("  ATTACK: rogue Wi-Fi network injected!")
        log.warning("=" * 60)
        with open('/tmp/wpa_addnetwork_log.txt', 'a') as f:
            f.write(f"AddNetwork #{self._net_count}: {cfg}\n")
        return dbus.ObjectPath(f'/fi/w1/wpa_supplicant1/Interfaces/0/Networks/{self._net_count}')

# ============================================================
# NA11 + NA13: 模拟 Firewall1 (INTERFACE omission + Properties.Set)
# ============================================================
class FakeFirewall1(dbus.service.Object):
    def __init__(self, bus):
        super().__init__(bus, '/com/example/Firewall1')
        self._rule_count = 0
        self._config = {"log_level": "info", "default_policy": "deny"}
        log.info("[Firewall1] registered at /com/example/Firewall1")

    @dbus.service.method('com.example.Firewall1.Control', in_signature='s', out_signature='s')
    def AddRule(self, rule_spec):
        self._rule_count += 1
        log.warning("=" * 60)
        log.warning("[Firewall1] AddRule('%s') (#%d)", rule_spec, self._rule_count)
        log.warning("  UID=%d (0=root)", os.getuid())
        log.warning("  ATTACK: firewall rule added by unprivileged user!")
        log.warning("=" * 60)
        with open('/tmp/firewall1_rules_log.txt', 'a') as f:
            f.write(f"AddRule #{self._rule_count}: {rule_spec}\n")
        return f"RULE ADDED: {rule_spec}"

    @dbus.service.method('org.freedesktop.DBus.Properties',
                         in_signature='ssv', out_signature='')
    def Set(self, interface_name, property_name, value):
        old = self._config.get(str(property_name), "(unset)")
        self._config[str(property_name)] = str(value)
        log.warning("=" * 60)
        log.warning("[Firewall1] Properties.Set('%s', '%s', '%s')", interface_name, property_name, value)
        log.warning("  old=%s → new=%s", old, value)
        log.warning("  UID=%d (0=root)", os.getuid())
        log.warning("  ATTACK: root config modified by unprivileged user!")
        log.warning("=" * 60)
        with open('/tmp/firewall1_propset_log.txt', 'a') as f:
            f.write(f"Set {property_name}: {old} → {value}\n")

# ============================================================
# NA12: Peer.Ping flood (测试用 — 不需要自定义服务，直接打 dbus-daemon)
# ============================================================

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()

    # 注册所有服务名
    names = [
        'org.freedesktop.UDisks2',
        'org.freedesktop.PackageKit',
        'fi.w1.wpa_supplicant1',
        'com.example.Firewall1',
        'org.freedesktop.NetworkManager',
    ]
    bus_names = []
    for n in names:
        try:
            bn = dbus.service.BusName(n, bus)
            bus_names.append(bn)
            log.info("Acquired name: %s", n)
        except Exception as e:
            log.error("Failed to acquire %s: %s", n, e)

    # 实例化服务
    udisks_mgr = FakeUDisks2Manager(bus)
    udisks_sda = FakeUDisks2Block(bus, "sda")
    udisks_sdb = FakeUDisks2Block(bus, "sdb")
    udisks_sdb1 = FakeUDisks2Block(bus, "sdb1")

    nm_conn1 = FakeNMConnection(bus, "1", {"802-11-wireless-security": "MyHomeWiFi_P@ss"})
    nm_conn2 = FakeNMConnection(bus, "2", {"vpn": "Corp_VPN_Secret_Key_12345"})
    nm_conn3 = FakeNMConnection(bus, "3", {"802-1x": "Enterprise_Cert_Password"})

    pk = FakePackageKit(bus)
    pk_tx = FakePackageKitTransaction(bus)

    wpa = FakeWpaSupplicant(bus)

    fw = FakeFirewall1(bus)

    log.info("All NA6-NA16 services started. Entering main loop...")
    GLib.MainLoop().run()

if __name__ == '__main__':
    main()
