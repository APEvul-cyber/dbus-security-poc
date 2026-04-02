#!/usr/bin/env python3
"""
PoC 5 目标服务: com.example.PowerManager1 (信号监听)

这个服务模拟一个特权 PowerManager，它监听 UDisks2 的 JobCompleted 信号。
漏洞: 服务仅根据 INTERFACE + MEMBER + PATH 匹配信号，不验证 SENDER。

攻击者可以伪造一个 SIGNAL 消息，设置:
  INTERFACE = "org.freedesktop.UDisks2.Manager"
  MEMBER = "JobCompleted"
  PATH = "/org/freedesktop/UDisks2"
来触发服务的特权操作。

使用方法:
  # 服务通过 systemd 自动启动
  systemctl status powermanager1-signal
  
  # 查看日志
  journalctl -u powermanager1-signal -f
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
    format='[PowerManager1-Signal] %(asctime)s %(levelname)s: %(message)s'
)
log = logging.getLogger('PowerManager1-Signal')


class PowerManagerSignalListener:
    """
    模拟的特权 PowerManager 服务
    监听 UDisks2 的 JobCompleted 信号并执行特权操作
    
    漏洞: 不验证信号的 SENDER，仅匹配 INTERFACE/MEMBER/PATH
    """

    def __init__(self, bus):
        self.bus = bus
        self.action_count = 0

        # 注册信号监听 — 关键: 仅匹配 interface, member, path
        # 没有 sender_keyword 过滤！
        bus.add_signal_receiver(
            self.on_job_completed,
            signal_name="JobCompleted",
            dbus_interface="org.freedesktop.UDisks2.Manager",
            path="/org/freedesktop/UDisks2",
            # 注意: 没有 bus_name 参数来限制 sender！
        )

        log.info("已注册信号监听:")
        log.info("  interface=org.freedesktop.UDisks2.Manager")
        log.info("  member=JobCompleted")
        log.info("  path=/org/freedesktop/UDisks2")
        log.info("  sender=<未限制> ← 这是漏洞点！")

    def on_job_completed(self, *args, **kwargs):
        """
        处理 JobCompleted 信号
        
        在真实场景中，这里会执行特权操作如:
        - 自动挂载设备
        - 运行备份钩子
        - 修改电源状态
        
        漏洞: 我们信任任何发送此信号的源
        """
        self.action_count += 1

        log.warning("=" * 60)
        log.warning("收到 JobCompleted 信号！(第 %d 次)", self.action_count)
        log.warning("信号参数: %s", args)
        log.warning("")
        log.warning("⚠️  服务正在执行特权操作...")
        log.warning("⚠️  如果这个信号不是来自真正的 UDisks2，")
        log.warning("⚠️  那么这就是一次成功的信号注入攻击！")
        log.warning("")
        log.warning("模拟特权操作: 自动挂载设备、运行备份钩子...")
        log.warning("当前 UID: %d (0=root)", os.getuid())
        log.warning("=" * 60)

        # 记录到文件（方便验证）
        with open("/tmp/signal-attack-log.txt", "a") as f:
            f.write(f"[{self.action_count}] JobCompleted signal received. args={args}\n")


def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    system_bus = dbus.SystemBus()

    # 请求 well-known name
    name = dbus.service.BusName('com.example.PowerManager1', system_bus)
    log.info("已获取 well-known name: com.example.PowerManager1")
    log.info("PID=%d, UID=%d", os.getpid(), os.getuid())

    # 创建信号监听器
    listener = PowerManagerSignalListener(system_bus)

    log.info("")
    log.info("服务已就绪，等待信号...")
    log.info("")
    log.info("测试方法 (以 attacker 用户):")
    log.info("  dbus-send --system --type=signal \\")
    log.info("    /org/freedesktop/UDisks2 \\")
    log.info("    org.freedesktop.UDisks2.Manager.JobCompleted \\")
    log.info("    string:'/org/freedesktop/UDisks2/jobs/999' \\")
    log.info("    boolean:true \\")
    log.info("    string:'Job completed successfully'")
    log.info("")

    loop = GLib.MainLoop()
    try:
        loop.run()
    except KeyboardInterrupt:
        log.info("服务关闭")
        loop.quit()


if __name__ == '__main__':
    main()
