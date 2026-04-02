#!/usr/bin/env python3
"""
模拟 com.ubuntu.USBCreator D-Bus 服务 (CVE-2013-1060 行为复现)

该服务复现了漏洞版本 usb-creator 的关键行为:
  - 以 root 身份运行
  - 在 system bus 上注册 com.ubuntu.USBCreator
  - 暴露 Image(source, target) 方法
  - 不做 polkit/权限检查，直接执行文件拷贝
  - 任何本地用户都可以调用

这使得非特权用户可以:
  - 以 root 权限将任意文件拷贝到任意位置
  - 读取 root 才能访问的文件（通过拷贝到用户可读位置）
"""

import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
import os
import shutil
import logging

logging.basicConfig(
    level=logging.INFO,
    format='[USBCreator] %(asctime)s %(levelname)s: %(message)s'
)
log = logging.getLogger('USBCreator')


class USBCreatorService(dbus.service.Object):
    """模拟漏洞版本的 USBCreator 服务"""

    def __init__(self, bus, object_path='/com/ubuntu/USBCreator'):
        super().__init__(bus, object_path)
        self._call_count = 0
        log.info("USBCreator 服务已启动")
        log.info("  PID=%d, UID=%d (0=root)", os.getpid(), os.getuid())
        log.info("  Bus name: com.ubuntu.USBCreator")
        log.info("  Object path: /com/ubuntu/USBCreator")
        log.info("  Interface: com.ubuntu.USBCreator")
        log.info("  暴露方法: Image(source, target)")
        log.info("  ⚠️  无 polkit 认证 — 任何本地用户可调用")

    @dbus.service.method(
        dbus_interface='com.ubuntu.USBCreator',
        in_signature='ss',
        out_signature='b'
    )
    def Image(self, source, target):
        """
        漏洞方法: 以 root 权限将 source 拷贝到 target

        在真实的 CVE-2013-1060 中，这个方法用于将 ISO 镜像写入 USB 设备。
        由于缺少 polkit 认证，攻击者可以:
          - source=/etc/shadow, target=/tmp/shadow_copy  → 读取敏感文件
          - source=/home/attacker/evil.img, target=/dev/sda → 覆写磁盘
        """
        self._call_count += 1
        log.warning("=" * 60)
        log.warning("Image() 方法被调用！(第 %d 次)", self._call_count)
        log.warning("  source = %s", source)
        log.warning("  target = %s", target)
        log.warning("  当前 UID = %d (以 root 权限执行)", os.getuid())
        log.warning("  ⚠️  无权限检查，直接执行文件拷贝！")

        try:
            # 安全限制: 不允许写入真正的块设备（防止容器内误操作）
            if target.startswith('/dev/') and target != '/dev/null':
                log.warning("  [安全限制] 拒绝写入块设备 %s（容器保护）", target)
                log.warning("  在真实漏洞中，这会成功写入！")
                return False

            # 执行文件拷贝（以 root 权限）
            shutil.copy2(str(source), str(target))
            log.warning("  ✓ 拷贝成功: %s → %s", source, target)
            log.warning("  如果调用者是非 root 用户，这就是权限提升！")
            log.warning("=" * 60)
            return True

        except Exception as e:
            log.error("  ✗ 拷贝失败: %s", e)
            log.warning("=" * 60)
            return False

    @dbus.service.method(
        dbus_interface='com.ubuntu.USBCreator',
        in_signature='',
        out_signature='s'
    )
    def Version(self):
        """返回版本信息（安全方法）"""
        log.info("Version() 被调用")
        return "USBCreator 0.2.47 (simulated vulnerable version)"

    @dbus.service.method(
        dbus_interface='com.ubuntu.USBCreator',
        in_signature='',
        out_signature='s'
    )
    def GetStatus(self):
        """返回状态（安全方法）"""
        log.info("GetStatus() 被调用")
        return f"running, Image() called {self._call_count} times"


def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    system_bus = dbus.SystemBus()

    name = dbus.service.BusName('com.ubuntu.USBCreator', system_bus)
    log.info("已获取 well-known name: com.ubuntu.USBCreator")

    service = USBCreatorService(system_bus)

    log.info("进入主循环，等待方法调用...")
    loop = GLib.MainLoop()
    try:
        loop.run()
    except KeyboardInterrupt:
        log.info("服务关闭")
        loop.quit()


if __name__ == '__main__':
    main()
