#!/bin/bash
# 容器 1 环境验证脚本
# 检查 D-Bus system bus 和 USBCreator 服务是否就绪

set -e

echo "=========================================="
echo " PoC 1 & 2 环境验证 (USBCreator)"
echo "=========================================="

# 1. 检查 dbus-daemon 是否运行
echo -n "[1] dbus-daemon 进程: "
if pgrep -x dbus-daemon > /dev/null 2>&1; then
    echo "✓ 运行中"
else
    echo "✗ 未运行，尝试启动..."
    systemctl start dbus
    sleep 1
    if pgrep -x dbus-daemon > /dev/null 2>&1; then
        echo "  → 已启动"
    else
        echo "  → 启动失败！"
        exit 1
    fi
fi

# 2. 检查 system bus socket
echo -n "[2] System bus socket: "
if [ -S /var/run/dbus/system_bus_socket ]; then
    echo "✓ 存在"
else
    echo "✗ 不存在"
    exit 1
fi

# 3. 检查 usb-creator 服务文件
echo -n "[3] USBCreator D-Bus 服务文件: "
if [ -f /usr/share/dbus-1/system-services/com.ubuntu.USBCreator.service ]; then
    echo "✓ 已安装"
    echo "    $(cat /usr/share/dbus-1/system-services/com.ubuntu.USBCreator.service | head -5)"
else
    echo "✗ 未找到"
    echo "    尝试查找相关文件..."
    find / -name "*USBCreator*" -o -name "*usb-creator*" 2>/dev/null | head -20
fi

# 4. 检查 D-Bus policy 文件
echo -n "[4] USBCreator D-Bus policy: "
POLICY_FILE=$(find /etc/dbus-1 /usr/share/dbus-1 -name "*USBCreator*" -o -name "*usb-creator*" 2>/dev/null | head -1)
if [ -n "$POLICY_FILE" ]; then
    echo "✓ 找到: $POLICY_FILE"
    echo "    --- policy 内容 ---"
    cat "$POLICY_FILE" 2>/dev/null || true
    echo "    --- end ---"
else
    echo "✗ 未找到 policy 文件"
fi

# 5. 尝试列出 system bus 上的服务
echo "[5] System bus 已注册服务:"
dbus-send --system --dest=org.freedesktop.DBus \
    --type=method_call --print-reply \
    /org/freedesktop/DBus org.freedesktop.DBus.ListNames 2>/dev/null | \
    grep -i "usb\|creator" || echo "    (USBCreator 服务可能需要按需激活)"

# 6. 尝试 introspect USBCreator
echo "[6] 尝试 Introspect com.ubuntu.USBCreator:"
dbus-send --system --dest=com.ubuntu.USBCreator \
    --type=method_call --print-reply \
    /com/ubuntu/USBCreator \
    org.freedesktop.DBus.Introspectable.Introspect 2>&1 || \
    echo "    (服务可能需要手动激活或 D-Bus activation)"

# 7. 检查 Python D-Bus
echo -n "[7] Python3 D-Bus 库: "
python3 -c "import dbus; print('✓ python3-dbus 版本:', dbus.version)" 2>/dev/null || echo "✗ 不可用"

# 8. 检查攻击者用户
echo -n "[8] 攻击者用户 'attacker': "
if id attacker > /dev/null 2>&1; then
    echo "✓ 存在 (uid=$(id -u attacker))"
else
    echo "✗ 不存在"
fi

echo ""
echo "=========================================="
echo " 验证完成。使用以下命令测试 PoC:"
echo "=========================================="
echo ""
echo "# 以 attacker 身份测试 PoC 1 (MEMBER=Image):"
echo "su - attacker -c 'dbus-send --system --dest=com.ubuntu.USBCreator --type=method_call --print-reply /com/ubuntu/USBCreator com.ubuntu.USBCreator.Image string:/home/attacker/test.img string:/dev/null'"
echo ""
echo "# 监控 D-Bus system bus:"
echo "dbus-monitor --system"
echo ""
