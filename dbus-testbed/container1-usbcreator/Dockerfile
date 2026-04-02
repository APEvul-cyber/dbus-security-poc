# ============================================================
# 容器 1: Ubuntu 22.04 + 模拟 USBCreator D-Bus 服务
# 用于验证 PoC 1 (MEMBER=Image) 和 PoC 2 (DESTINATION=com.ubuntu.USBCreator)
#
# 由于 usb-creator-common 在 ARM64 上不可用，
# 我们自行实现一个行为等价的 D-Bus 服务来复现 CVE-2013-1060 的逻辑:
#   - 以 root 运行
#   - 暴露 com.ubuntu.USBCreator 接口的 Image 方法
#   - 不做 polkit 认证（模拟漏洞版本的行为）
#   - Image 方法接受 source 和 target 参数并执行文件拷贝
# ============================================================
FROM jrei/systemd-ubuntu:22.04

LABEL description="D-Bus PoC 1&2: USBCreator privilege escalation (CVE-2013-1060 simulation)"

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    # D-Bus 核心
    dbus \
    dbus-x11 \
    # Python D-Bus 库
    python3 \
    python3-dbus \
    python3-gi \
    gir1.2-glib-2.0 \
    # 调试工具
    strace \
    gdb \
    # 通用工具
    vim \
    less \
    net-tools \
    iproute2 \
    procps \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# 创建测试用的攻击者用户
RUN useradd -m -s /bin/bash attacker && \
    echo "attacker:attacker" | chpasswd

# 创建测试文件
RUN dd if=/dev/zero of=/home/attacker/test.img bs=1M count=1 && \
    chown attacker:attacker /home/attacker/test.img && \
    echo "SENSITIVE_ROOT_DATA" > /root/secret.txt && \
    chmod 600 /root/secret.txt

# 部署模拟的 USBCreator D-Bus 服务
COPY usb-creator-service.py /usr/local/bin/usb-creator-service.py
RUN chmod +x /usr/local/bin/usb-creator-service.py

# D-Bus 服务激活文件
COPY com.ubuntu.USBCreator.service /usr/share/dbus-1/system-services/com.ubuntu.USBCreator.service

# D-Bus 策略文件（模拟漏洞版本: 允许任何本地用户调用）
COPY com.ubuntu.USBCreator.conf /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf

# systemd unit
COPY usb-creator-dbus.service /etc/systemd/system/usb-creator-dbus.service

RUN systemctl enable dbus && \
    systemctl enable usb-creator-dbus

# 验证脚本
COPY entrypoint-check.sh /usr/local/bin/entrypoint-check.sh
RUN chmod +x /usr/local/bin/entrypoint-check.sh

WORKDIR /opt/poc-reports
