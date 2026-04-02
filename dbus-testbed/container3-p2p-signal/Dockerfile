# ============================================================
# 容器 3: Ubuntu 22.04 + Python D-Bus
# 用于验证:
#   PoC 4: P2P 模式下伪造 SENDER header
#   PoC 5: 伪造 SIGNAL 的 INTERFACE 字段注入恶意信号
# ============================================================
FROM jrei/systemd-ubuntu:22.04

LABEL description="D-Bus PoC 4&5: SENDER spoofing (P2P) & SIGNAL INTERFACE spoofing"

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    # D-Bus 核心
    dbus \
    dbus-x11 \
    # Python D-Bus 库（两套绑定都装）
    python3 \
    python3-pip \
    python3-dbus \
    python3-gi \
    python3-gi-cairo \
    gir1.2-glib-2.0 \
    # 用于构造原始 D-Bus 消息
    python3-dev \
    # 调试工具
    strace \
    gdb \
    # 网络工具（P2P socket 调试）
    socat \
    netcat-openbsd \
    # 通用工具
    vim \
    less \
    net-tools \
    iproute2 \
    procps \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# 创建测试用户
RUN useradd -m -s /bin/bash attacker && \
    echo "attacker:attacker" | chpasswd && \
    useradd -m -s /bin/bash victim && \
    echo "victim:victim" | chpasswd

# ---- PoC 4: P2P PasswordVault 服务 ----
COPY passwordvault-p2p-server.py /usr/local/bin/passwordvault-p2p-server.py
RUN chmod +x /usr/local/bin/passwordvault-p2p-server.py

# ---- PoC 5: 信号监听服务 (模拟 PowerManager 监听 UDisks2 信号) ----
COPY signal-listener-service.py /usr/local/bin/signal-listener-service.py
RUN chmod +x /usr/local/bin/signal-listener-service.py

# PoC 5 的 D-Bus 服务和策略文件
COPY com.example.PowerManager1.conf /etc/dbus-1/system.d/com.example.PowerManager1.conf
COPY com.example.PowerManager1.service /usr/share/dbus-1/system-services/com.example.PowerManager1.service
COPY powermanager1-signal.service /etc/systemd/system/powermanager1-signal.service

# P2P socket 目录
RUN mkdir -p /run/passwordvault1 && chmod 777 /run/passwordvault1

# 启用服务
RUN systemctl enable dbus && \
    systemctl enable powermanager1-signal

# 验证脚本
COPY entrypoint-check.sh /usr/local/bin/entrypoint-check.sh
RUN chmod +x /usr/local/bin/entrypoint-check.sh

WORKDIR /opt/poc-reports
