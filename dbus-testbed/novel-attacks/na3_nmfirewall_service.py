#!/usr/bin/env python3
"""
Novel Attack 3 目标服务: com.example.NMFirewallHelper
漏洞: 信任 METHOD_CALL 的 INTERFACE 字段判断来源是 NetworkManager
攻击: 设置 INTERFACE=org.freedesktop.NetworkManager 调用 StateChanged
      触发 root 服务修改防火墙规则
"""
import dbus, dbus.service, dbus.mainloop.glib
from gi.repository import GLib
import os, logging

logging.basicConfig(level=logging.INFO, format='[NMFirewallHelper] %(asctime)s %(levelname)s: %(message)s')
log = logging.getLogger('NMFirewallHelper')

class NMFirewallHelperService(dbus.service.Object):
    def __init__(self, bus):
        super().__init__(bus, '/org/freedesktop/NetworkManager')
        self._fw_changes = 0
        log.info("NMFirewallHelper started, PID=%d, UID=%d", os.getpid(), os.getuid())
        log.info("Listening on PATH=/org/freedesktop/NetworkManager")
        log.info("WARNING: trusts INTERFACE field as identity proof!")

    @dbus.service.method(
        dbus_interface='org.freedesktop.NetworkManager',
        in_signature='u', out_signature='s'
    )
    def StateChanged(self, new_state):
        self._fw_changes += 1
        log.warning("=" * 60)
        log.warning("StateChanged(%d) called! (#%d)", new_state, self._fw_changes)
        log.warning("  UID=%d (0=root)", os.getuid())
        log.warning("  Trusting INTERFACE=org.freedesktop.NetworkManager as identity")
        log.warning("  Modifying firewall rules based on state=%d...", new_state)
        action = "UNKNOWN"
        if new_state == 70:
            action = "OPENING all ports (state=70=connected_global)"
            log.warning("  ACTION: %s", action)
        elif new_state == 20:
            action = "CLOSING all ports (state=20=disconnected)"
            log.warning("  ACTION: %s", action)
        else:
            action = f"Adjusting rules for state={new_state}"
            log.warning("  ACTION: %s", action)
        log.warning("  ATTACK SUCCESSFUL if caller is not NetworkManager!")
        log.warning("=" * 60)
        with open('/tmp/firewall_changes.txt', 'a') as f:
            f.write(f"#{self._fw_changes} state={new_state} action={action}\n")
        return f"Firewall updated: {action}"

    @dbus.service.method('com.example.NMFirewallHelper', in_signature='', out_signature='s')
    def GetStatus(self):
        return f"running, fw_changes={self._fw_changes}"

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    name = dbus.service.BusName('com.example.NMFirewallHelper', bus)
    svc = NMFirewallHelperService(bus)
    log.info("Entering main loop...")
    GLib.MainLoop().run()

if __name__ == '__main__':
    main()
