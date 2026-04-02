#!/bin/bash
# 容器 2 环境验证脚本
# 检查自定义 PowerManager1 服务和 send_interface ACL

set -e

echo "=========================================="
echo " PoC 3 环境验证 (INTERFACE ACL Bypass)"
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

# 3. 检查 PowerManager1 服务
echo -n "[3] PowerManager1 systemd 服务: "
if systemctl is-active --quiet powermanager1 2>/dev/null; then
    echo "✓ 运行中"
else
    echo "尝试启动..."
    systemctl start powermanager1 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet powermanager1 2>/dev/null; then
        echo "  → ✓ 已启动"
    else
        echo "  → ✗ 启动失败，查看日志:"
        journalctl -u powermanager1 --no-pager -n 10 2>/dev/null || true
    fi
fi

# 4. 检查 D-Bus policy 文件
echo "[4] D-Bus policy 文件:"
echo "    --- /etc/dbus-1/system.d/org.example.PowerManager1.conf ---"
cat /etc/dbus-1/system.d/org.example.PowerManager1.conf 2>/dev/null | head -30
echo "    --- end ---"

# 5. 检查服务是否在 system bus 上注册
echo "[5] 检查 org.example.PowerManager1 是否在 system bus 上:"
dbus-send --system --dest=org.freedesktop.DBus \
    --type=method_call --print-reply \
    /org/freedesktop/DBus org.freedesktop.DBus.ListNames 2>/dev/null | \
    grep -i "PowerManager" || echo "    (未找到，可能需要等待激活)"

# 6. 测试正常调用（带 INTERFACE，应该被 deny）
echo ""
echo "[6] 测试: 带 INTERFACE 的 PowerOff 调用（应该被拒绝）:"
su - attacker -c 'dbus-send --system \
    --dest=org.example.PowerManager1 \
    --type=method_call --print-reply \
    /org/example/PowerManager1 \
    org.example.PowerManager1.Manager.PowerOff 2>&1' || true

# 7. 测试安全方法
echo ""
echo "[7] 测试: GetStatus 调用（应该成功）:"
dbus-send --system \
    --dest=org.example.PowerManager1 \
    --type=method_call --print-reply \
    /org/example/PowerManager1 \
    org.example.PowerManager1.Manager.GetStatus 2>&1 || true

# 8. Python D-Bus
echo ""
echo -n "[8] Python3 D-Bus 库: "
python3 -c "import dbus; print('✓ python3-dbus 版本:', dbus.version)" 2>/dev/null || echo "✗ 不可用"

echo ""
echo "=========================================="
echo " 验证完成。PoC 3 测试方法:"
echo "=========================================="
echo ""
echo "# 正常调用（带 INTERFACE，应被 ACL 拒绝）:"
echo "su - attacker -c 'dbus-send --system --dest=org.example.PowerManager1 --type=method_call --print-reply /org/example/PowerManager1 org.example.PowerManager1.Manager.PowerOff'"
echo ""
echo "# 注意: dbus-send 无法省略 INTERFACE header（它从方法名中提取）。"
echo "# 要测试省略 INTERFACE 的绕过，需要使用 Python 或 C 编写原始 D-Bus 消息。"
echo "# 参见 /opt/poc-reports/METHOD_CALL_INTERFACE_result.txt"
echo ""
