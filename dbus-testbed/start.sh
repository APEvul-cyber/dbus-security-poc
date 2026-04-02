#!/bin/bash
# ============================================================
# D-Bus 协议安全 PoC 验证环境 — 一键启动脚本
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================"
echo " D-Bus 安全 PoC 验证环境"
echo "============================================"
echo ""

# 检查 Docker
if ! command -v docker &> /dev/null; then
    echo "❌ 未找到 docker，请先安装 Docker Desktop"
    exit 1
fi

if ! docker info &> /dev/null 2>&1; then
    echo "❌ Docker daemon 未运行，请启动 Docker Desktop"
    exit 1
fi

# 检查 b_results 目录
if [ ! -d "../b_results" ]; then
    echo "❌ 未找到 ../b_results/ 目录（PoC 报告文件）"
    exit 1
fi

# 创建符号链接（如果不存在）
if [ ! -e "./b_results" ]; then
    ln -sf ../b_results ./b_results
    echo "✓ 已链接 b_results → ../b_results"
fi

echo ""
echo "📦 构建容器镜像..."
echo ""

docker compose build --parallel

echo ""
echo "🚀 启动所有容器..."
echo ""

docker compose up -d

echo ""
echo "⏳ 等待 systemd 和 D-Bus 初始化 (15秒)..."
sleep 15

echo ""
echo "============================================"
echo " 容器状态"
echo "============================================"
docker compose ps

echo ""
echo "============================================"
echo " 环境验证"
echo "============================================"

echo ""
echo "--- 容器 1: PoC 1 & 2 (USBCreator) ---"
docker compose exec poc12-usbcreator bash -c '/usr/local/bin/entrypoint-check.sh' 2>/dev/null || echo "  (验证脚本执行失败，请手动进入容器检查)"

echo ""
echo "--- 容器 2: PoC 3 (INTERFACE ACL Bypass) ---"
docker compose exec poc3-interface-acl bash -c '/usr/local/bin/entrypoint-check.sh' 2>/dev/null || echo "  (验证脚本执行失败，请手动进入容器检查)"

echo ""
echo "--- 容器 3: PoC 4 & 5 (P2P SENDER / SIGNAL) ---"
docker compose exec poc45-p2p-signal bash -c '/usr/local/bin/entrypoint-check.sh' 2>/dev/null || echo "  (验证脚本执行失败，请手动进入容器检查)"

echo ""
echo "============================================"
echo " 使用方法"
echo "============================================"
echo ""
echo "# 进入容器 1 (PoC 1 & 2 — USBCreator):"
echo "docker compose exec poc12-usbcreator bash"
echo ""
echo "# 进入容器 2 (PoC 3 — INTERFACE ACL Bypass):"
echo "docker compose exec poc3-interface-acl bash"
echo ""
echo "# 进入容器 3 (PoC 4 & 5 — P2P/Signal):"
echo "docker compose exec poc45-p2p-signal bash"
echo ""
echo "# 查看 PoC 报告 (容器内):"
echo "ls /opt/poc-reports/"
echo ""
echo "# 停止所有容器:"
echo "docker compose down"
echo ""
