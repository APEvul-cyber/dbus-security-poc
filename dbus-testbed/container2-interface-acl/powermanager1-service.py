#!/usr/bin/env python3
"""
org.example.PowerManager1 — 自定义 D-Bus 服务
用于验证 PoC 3: 省略 INTERFACE header 绕过 send_interface ACL

该服务暴露以下方法:
  - org.example.PowerManager1.Manager.GetStatus()  → 返回状态（安全方法）
  - org.example.PowerManager1.Manager.PowerOff()    → 模拟关机（敏感方法）

PowerOff 方法在 D-Bus policy 中通过 send_interface 规则限制，
但如果攻击者省略 INTERFACE header，deny 规则不会匹配。
"""

import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
import os
import sys
import logging

logging.basicConfig(
    level=logging.INFO,
    format='[PowerManager1] %(asctime)s %(levelname)s: %(message)s'
)
log = logging.getLogger('PowerManager1')


class PowerManager1Service(dbus.service.Object):
    """模拟的特权电源管理服务"""

    def __init__(self, bus, object_path='/org/example/PowerManager1'):
        super().__init__(bus, object_path)
        self._status = "running"
        self._poweroff_count = 0
        log.info("PowerManager1 服务已启动，PID=%d, UID=%d", os.getpid(), os.getuid())
        log.info("对象路径: %s", object_path)
        log.info("接口: org.example.PowerManager1.Manager")

    @dbus.service.method(
        dbus_interface='org.example.PowerManager1.Manager',
        in_signature='',
        out_signature='s'
    )
    def GetStatus(self):
        """安全方法: 返回当前状态"""
        log.info("GetStatus() 被调用 — 这是安全操作")
        return f"status={self._status}, poweroff_attempts={self._poweroff_count}"

    @dbus.service.method(
        dbus_interface='org.example.PowerManager1.Manager',
        in_signature='',
        out_signature='s'
    )
    def PowerOff(self):
        """
        敏感方法: 模拟关机操作
        
        在真实场景中，这会执行 /sbin/poweroff 或 reboot(RB_POWER_OFF)。
        这里仅记录日志并返回结果，不真正关机。
        
        D-Bus policy 通过 send_interface 限制此方法，
        但省略 INTERFACE header 可以绕过该限制。
        """
        self._poweroff_count += 1
        caller = "unknown"
        log.warning("=" * 60)
        log.warning("PowerOff() 被调用！这是敏感操作！")
        log.warning("调用次数: %d", self._poweroff_count)
        log.warning("当前 UID: %d (0=root)", os.getuid())
        log.warning("如果这是非授权调用，说明 ACL 被绕过了！")
        log.warning("=" * 60)
        return f"POWEROFF_EXECUTED (attempt #{self._poweroff_count}) — 如果你是非 root 用户看到此消息，说明 send_interface ACL 被绕过！"

    @dbus.service.method(
        dbus_interface='org.example.PowerManager1.Manager',
        in_signature='',
        out_signature='s'
    )
    def Ping(self):
        """健康检查方法"""
        log.info("Ping() 被调用")
        return "pong"


def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    system_bus = dbus.SystemBus()

    # 请求 well-known name
    name = dbus.service.BusName('org.example.PowerManager1', system_bus)
    log.info("已获取 well-known name: org.example.PowerManager1")

    # 创建服务对象
    service = PowerManager1Service(system_bus)

    # 运行主循环
    log.info("进入主循环，等待方法调用...")
    loop = GLib.MainLoop()
    try:
        loop.run()
    except KeyboardInterrupt:
        log.info("收到中断信号，退出")
        loop.quit()


if __name__ == '__main__':
    main()
