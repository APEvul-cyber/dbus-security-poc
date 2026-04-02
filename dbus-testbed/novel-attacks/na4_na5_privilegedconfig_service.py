#!/usr/bin/env python3
"""
Novel Attack 4 目标服务: com.example.PrivilegedConfig1
漏洞: 根据 SIGNATURE header 选择不同的处理路径
      SIGNATURE=a{sv} → 严格验证; SIGNATURE=ay → 直接写入配置文件
攻击: 发送 SIGNATURE=ay 的 SetConfig 调用，绕过验证直接写入 root 配置
"""
import dbus, dbus.service, dbus.mainloop.glib
from gi.repository import GLib
import os, logging

logging.basicConfig(level=logging.INFO, format='[PrivilegedConfig1] %(asctime)s %(levelname)s: %(message)s')
log = logging.getLogger('PrivilegedConfig1')

class PrivilegedConfigService(dbus.service.Object):
    def __init__(self, bus):
        super().__init__(bus, '/com/example/PrivilegedConfig1')
        self._write_count = 0
        log.info("PrivilegedConfig1 started, PID=%d, UID=%d", os.getpid(), os.getuid())
        log.info("Exposes SetConfig with two paths:")
        log.info("  SIGNATURE=a{sv} → strict validation")
        log.info("  SIGNATURE=ay → raw blob write (VULNERABLE)")

    @dbus.service.method(
        dbus_interface='com.example.PrivilegedConfig1.Settings',
        in_signature='a{sv}', out_signature='s'
    )
    def SetConfig(self, config_dict):
        """Safe path: strict validation"""
        log.info("SetConfig(a{sv}) called — strict validation path")
        allowed_keys = {"theme", "language", "font_size"}
        for key in config_dict:
            if key not in allowed_keys:
                log.info("  Rejected: unknown key '%s'", key)
                return f"REJECTED: unknown key '{key}'"
        log.info("  Accepted: %s", dict(config_dict))
        return "OK (validated)"

    @dbus.service.method(
        dbus_interface='com.example.PrivilegedConfig1.Settings',
        in_signature='ay', out_signature='s',
        byte_arrays=True
    )
    def SetConfigRaw(self, raw_bytes):
        """Vulnerable path: raw blob write"""
        self._write_count += 1
        log.warning("=" * 60)
        log.warning("SetConfigRaw(ay) called! (#%d)", self._write_count)
        log.warning("  UID=%d (0=root)", os.getuid())
        log.warning("  Raw bytes length: %d", len(raw_bytes))
        log.warning("  Writing directly to /tmp/privileged_config.conf...")
        content = bytes(raw_bytes).decode('utf-8', errors='replace')
        log.warning("  Content:\n%s", content[:500])
        with open('/tmp/privileged_config.conf', 'w') as f:
            f.write(content)
        log.warning("  Written! ATTACK SUCCESSFUL if caller is unprivileged!")
        log.warning("=" * 60)
        return f"RAW CONFIG WRITTEN ({len(raw_bytes)} bytes)"

    @dbus.service.method(
        dbus_interface='org.freedesktop.DBus.Properties',
        in_signature='s', out_signature='a{sv}'
    )
    def GetAll(self, interface_name):
        """Properties.GetAll — exposes sensitive data"""
        log.warning("GetAll('%s') called!", interface_name)
        if interface_name == "com.example.PrivilegedConfig1.Secrets":
            secrets = {
                "db_password": dbus.String("r00t_db_p@ss", variant_level=1),
                "api_key": dbus.String("sk-secret-api-key-12345", variant_level=1),
                "private_key_path": dbus.String("/etc/ssl/private/server.key", variant_level=1),
            }
            log.warning("  Returning secrets for interface: %s", interface_name)
            log.warning("  ATTACK SUCCESSFUL if ACL was bypassed!")
            return dbus.Dictionary(secrets, signature='sv')
        return dbus.Dictionary({}, signature='sv')

    @dbus.service.method('com.example.PrivilegedConfig1', in_signature='', out_signature='s')
    def GetStatus(self):
        return f"running, raw_writes={self._write_count}"

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    name = dbus.service.BusName('com.example.PrivilegedConfig1', bus)
    svc = PrivilegedConfigService(bus)
    log.info("Entering main loop...")
    GLib.MainLoop().run()

if __name__ == '__main__':
    main()
