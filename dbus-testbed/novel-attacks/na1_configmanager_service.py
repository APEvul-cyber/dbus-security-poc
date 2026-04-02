#!/usr/bin/env python3
"""
Novel Attack 1 目标服务: org.example.ConfigManager1
漏洞: 信任 SIGNAL 的 PATH 字段作为来源验证，不检查 SENDER
攻击: 伪造 PATH=/org/example/ConfigManager1 的 ConfigFileChanged 信号
      触发 root 服务重载攻击者控制的配置文件
"""
import dbus, dbus.service, dbus.mainloop.glib
from gi.repository import GLib
import os, logging

logging.basicConfig(level=logging.INFO, format='[ConfigManager1] %(asctime)s %(levelname)s: %(message)s')
log = logging.getLogger('ConfigManager1')

class ConfigManagerService(dbus.service.Object):
    def __init__(self, bus):
        super().__init__(bus, '/org/example/ConfigManager1')
        self._reload_count = 0
        # 监听 ConfigFileChanged 信号 — 不验证 SENDER！
        bus.add_signal_receiver(
            self.on_config_changed,
            signal_name="ConfigFileChanged",
            dbus_interface="org.example.ConfigManager1",
            path="/org/example/ConfigManager1",
        )
        log.info("ConfigManager1 started, PID=%d, UID=%d", os.getpid(), os.getuid())
        log.info("Listening for ConfigFileChanged signal on PATH=/org/example/ConfigManager1")
        log.info("WARNING: No SENDER verification!")

    def on_config_changed(self, config_path):
        self._reload_count += 1
        log.warning("=" * 60)
        log.warning("ConfigFileChanged signal received! (#%d)", self._reload_count)
        log.warning("  config_path = %s", config_path)
        log.warning("  Running as UID=%d (0=root)", os.getuid())
        log.warning("  Attempting to reload config as root...")
        try:
            if os.path.exists(str(config_path)):
                with open(str(config_path), 'r') as f:
                    content = f.read()
                log.warning("  Config content:\n%s", content[:500])
                with open('/tmp/configmanager_loaded.conf', 'w') as f:
                    f.write(content)
                log.warning("  Config written to /tmp/configmanager_loaded.conf")
                log.warning("  ATTACK SUCCESSFUL if this was from an unprivileged user!")
            else:
                log.warning("  File not found: %s", config_path)
        except Exception as e:
            log.error("  Error: %s", e)
        log.warning("=" * 60)

    @dbus.service.method('org.example.ConfigManager1', in_signature='', out_signature='s')
    def GetStatus(self):
        return f"running, reloads={self._reload_count}"

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    name = dbus.service.BusName('org.example.ConfigManager1', bus)
    svc = ConfigManagerService(bus)
    log.info("Entering main loop...")
    GLib.MainLoop().run()

if __name__ == '__main__':
    main()
