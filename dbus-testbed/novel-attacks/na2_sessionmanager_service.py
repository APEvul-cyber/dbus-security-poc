#!/usr/bin/env python3
"""
Novel Attack 2 目标服务: com.example.SessionManager1
漏洞: 监听 NameOwnerChanged 信号但不验证 SENDER==org.freedesktop.DBus
攻击: 伪造 NameOwnerChanged 信号使服务认为 LockHelper 已退出，触发解锁
"""
import dbus, dbus.service, dbus.mainloop.glib
from gi.repository import GLib
import os, logging

logging.basicConfig(level=logging.INFO, format='[SessionManager1] %(asctime)s %(levelname)s: %(message)s')
log = logging.getLogger('SessionManager1')

class SessionManagerService(dbus.service.Object):
    def __init__(self, bus):
        super().__init__(bus, '/com/example/SessionManager1')
        self._locked = True
        self._unlock_count = 0
        # 监听 NameOwnerChanged — 不验证 SENDER！
        bus.add_signal_receiver(
            self.on_name_owner_changed,
            signal_name="NameOwnerChanged",
            dbus_interface="org.freedesktop.DBus",
            path="/org/freedesktop/DBus",
        )
        log.info("SessionManager1 started, PID=%d, UID=%d", os.getpid(), os.getuid())
        log.info("Session is LOCKED (waiting for LockHelper1)")
        log.info("Listening for NameOwnerChanged — WARNING: no SENDER check!")

    def on_name_owner_changed(self, name, old_owner, new_owner):
        log.info("NameOwnerChanged: name=%s old=%s new=%s", name, old_owner, new_owner)
        if str(name) == "com.example.LockHelper1" and str(new_owner) == "":
            self._unlock_count += 1
            self._locked = False
            log.warning("=" * 60)
            log.warning("LockHelper1 disappeared! Unlocking session! (#%d)", self._unlock_count)
            log.warning("  Session state: UNLOCKED")
            log.warning("  UID=%d (0=root)", os.getuid())
            log.warning("  If this signal was spoofed, session security is bypassed!")
            log.warning("=" * 60)
            with open('/tmp/session_unlocked.txt', 'a') as f:
                f.write(f"Session unlocked #{self._unlock_count} by NameOwnerChanged\n")

    @dbus.service.method('com.example.SessionManager1', in_signature='', out_signature='s')
    def GetStatus(self):
        return f"locked={self._locked}, unlock_count={self._unlock_count}"

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    name = dbus.service.BusName('com.example.SessionManager1', bus)
    svc = SessionManagerService(bus)
    log.info("Entering main loop...")
    GLib.MainLoop().run()

if __name__ == '__main__':
    main()
