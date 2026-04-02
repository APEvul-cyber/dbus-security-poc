#!/bin/bash
# 容器 3 环境验证脚本
# 检查 P2P PasswordVault 服务和 Signal 监听服务

set -e

echo "=========================================="
echo " PoC 4 & 5 环境验证"
echo "=========================================="

# 1. 检查 dbus-daemon
echo -n "[1] dbus-daemon 进程: "
if pgrep -x dbus-daemon > /dev/null 2>&1; then
    echo "✓ 运行中"
else
    echo "✗ 未运行，尝试启动..."
    systemctl start dbus
    sleep 1
fi

# 2. 检查 system bus socket
echo -n "[2] System bus socket: "
if [ -S /run/dbus/system_bus_socket ] || [ -S /var/run/dbus/system_bus_socket ]; then
    echo "✓ 存在"
else
    echo "✗ 不存在"
fi

# 3. 检查 PowerManager1 信号监听服务
echo -n "[3] PowerManager1 信号监听服务: "
if systemctl is-active --quiet powermanager1-signal 2>/dev/null; then
    echo "✓ 运行中"
else
    echo "尝试启动..."
    systemctl start powermanager1-signal 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet powermanager1-signal 2>/dev/null; then
        echo "  → ✓ 已启动"
    else
        echo "  → ✗ 启动失败"
        journalctl -u powermanager1-signal --no-pager -n 10 2>/dev/null || true
    fi
fi

# 4. 检查 P2P socket 目录
echo -n "[4] P2P socket 目录: "
if [ -d /run/passwordvault1 ]; then
    echo "✓ 存在"
else
    echo "✗ 不存在，创建中..."
    mkdir -p /run/passwordvault1 && chmod 777 /run/passwordvault1
fi

# 5. Python D-Bus 库
echo -n "[5] Python3 D-Bus 库: "
python3 -c "import dbus; print('✓ python3-dbus 版本:', dbus.version)" 2>/dev/null || echo "✗ 不可用"

echo -n "    Python3 GI (GDBus): "
python3 -c "from gi.repository import Gio; print('✓ GDBus 可用')" 2>/dev/null || echo "✗ 不可用"

# 6. 检查用户
echo -n "[6] 用户 'attacker': "
id attacker 2>/dev/null && echo "" || echo "✗ 不存在"
echo -n "    用户 'victim': "
id victim 2>/dev/null && echo "" || echo "✗ 不存在"

# 7. 检查 socat
echo -n "[7] socat (P2P socket 工具): "
which socat > /dev/null 2>&1 && echo "✓ 已安装" || echo "✗ 未安装"

echo ""
echo "=========================================="
echo " PoC 4 测试方法 (SENDER 伪造 - P2P 模式):"
echo "=========================================="
echo ""
echo "# 1. 启动 P2P PasswordVault 服务 (root):"
echo "python3 /usr/local/bin/passwordvault-p2p-server.py &"
echo ""
echo "# 2. 以 attacker 身份连接并伪造 SENDER:"
echo "# 需要编写 Python 脚本构造原始 D-Bus 消息"
echo "# 参见 /opt/poc-reports/METHOD_CALL_SENDER_result.txt"
echo ""
echo "=========================================="
echo " PoC 5 测试方法 (SIGNAL INTERFACE 欺骗):"
echo "=========================================="
echo ""
echo "# 以 attacker 身份发送伪造的 UDisks2 信号:"
echo "su - attacker -c 'dbus-send --system --type=signal \\"
echo "  /org/freedesktop/UDisks2 \\"
echo "  org.freedesktop.UDisks2.Manager.JobCompleted \\"
echo "  string:\"/org/freedesktop/UDisks2/jobs/999\" \\"
echo "  boolean:true \\"
echo "  string:\"Job completed successfully\"'"
echo ""
echo "# 查看服务是否收到信号:"
echo "journalctl -u powermanager1-signal -f"
echo "cat /tmp/signal-attack-log.txt"
echo ""
