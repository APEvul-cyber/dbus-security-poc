# ============================================================
# 容器 2: Ubuntu 22.04 + 自定义 D-Bus 服务
# 用于验证 PoC 3: 省略 INTERFACE header 绕过 send_interface ACL
# 基于 CVE-2008-0595 原理
# ============================================================
FROM jrei/systemd-ubuntu:22.04

LABEL description="D-Bus PoC 3: INTERFACE omission bypasses send_interface ACL"

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    # D-Bus 核心
    dbus \
    dbus-x11 \
    # Python D-Bus 库
    python3 \
    python3-dbus \
    python3-gi \
    python3-gi-cairo \
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

# 创建测试用户
RUN useradd -m -s /bin/bash attacker && \
    echo "attacker:attacker" | chpasswd

# ---- 部署自定义 D-Bus 服务: org.example.PowerManager1 ----

# 1. D-Bus 服务激活文件
COPY org.example.PowerManager1.service /usr/share/dbus-1/system-services/org.example.PowerManager1.service

# 2. D-Bus 安全策略文件（故意使用有缺陷的 send_interface ACL）
COPY org.example.PowerManager1.conf /etc/dbus-1/system.d/org.example.PowerManager1.conf

# 3. 服务实现（Python）
COPY powermanager1-service.py /usr/local/bin/powermanager1-service.py
RUN chmod +x /usr/local/bin/powermanager1-service.py

# 4. systemd unit 文件
COPY powermanager1.service /etc/systemd/system/powermanager1.service
RUN systemctl enable dbus && \
    systemctl enable powermanager1

# 验证脚本
COPY entrypoint-check.sh /usr/local/bin/entrypoint-check.sh
RUN chmod +x /usr/local/bin/entrypoint-check.sh

WORKDIR /opt/poc-reports
