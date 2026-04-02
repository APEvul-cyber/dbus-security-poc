# D-Bus 协议安全 PoC 验证报告

## 概述

本项目通过自动化 pipeline 生成了 5 个 D-Bus 协议的安全分析报告，每个报告描述了一种利用 D-Bus 消息 header field 的攻击场景。我们搭建了 Docker 容器环境对这些 PoC 进行了手动验证。

## 测试结果

| PoC | 攻击场景 | 关键字段 | 结果 |
|-----|---------|---------|------|
| PoC 1 | USBCreator `Image` 方法权限提升 (CVE-2013-1060) | `MEMBER=Image` | ✅ 成功复现 |
| PoC 2 | USBCreator `DESTINATION` 路由攻击 | `DESTINATION=com.ubuntu.USBCreator` | ✅ 成功复现 |
| PoC 3 | 省略 `INTERFACE` 绕过 `send_interface` ACL (CVE-2008-0595) | `INTERFACE=(omitted)` | ❌ 无法复现 |
| PoC 4 | P2P 模式 `SENDER` 伪造 | `SENDER=:1.42` | ✅ 成功复现 |
| PoC 5 | `SIGNAL` 的 `INTERFACE` 欺骗注入 | `INTERFACE=org.freedesktop.UDisks2.Manager` | ✅ 成功复现 |

**总计: 4/5 成功复现，1/5 因 CVE 已修复无法复现。**

## 各 PoC 详情

### PoC 1 — MEMBER=Image 权限提升 ✅

- 非特权用户 `attacker`(uid=1000) 通过 D-Bus system bus 调用 `com.ubuntu.USBCreator.Image` 方法
- 服务以 root(uid=0) 执行文件拷贝，成功将 `/root/secret.txt` 和 `/etc/shadow` 拷贝到 attacker 可访问的位置
- 关键: `MEMBER` 字段选择了特权代码路径，其他方法 (Version/GetStatus) 不触发漏洞

### PoC 2 — DESTINATION 路由攻击 ✅

- `DESTINATION=com.ubuntu.USBCreator` 将消息路由到 root 权限服务，攻击成功
- `DESTINATION=com.ubuntu.WRONG_SERVICE` → `ServiceUnknown` 错误，攻击失败
- `DESTINATION=org.freedesktop.DBus` → `AccessDenied`，攻击失败
- 关键: `DESTINATION` 是将消息送达特权服务的必要条件

### PoC 3 — 省略 INTERFACE 绕过 ACL ❌

- dbus-daemon 1.12.20 已修复 CVE-2008-0595
- 带 `INTERFACE` 的 `PowerOff` 调用 → `AccessDenied` ✓
- 省略 `INTERFACE` 的 `PowerOff` 调用 → `AccessDenied` ✓（修复后也被拦截）
- 修复机制: `send_interface` deny 规则现在也匹配 `interface=(unset)` 的消息
- 要复现需要 dbus-daemon < 1.2.4（2008 年之前的版本）

### PoC 4 — P2P 模式 SENDER 伪造 ✅

- attacker 连接 P2P Unix socket，伪造 `SENDER=:1.42`（受害者身份）
- 服务返回受害者的全部密钥: 银行密码、邮箱密码、SSH 私钥
- 伪造 `SENDER=:1.100` 获取了管理员的 admin-token 和数据库密码
- 关键: P2P 模式下无 bus daemon 验证 SENDER，服务端错误信任导致身份冒充

### PoC 5 — SIGNAL INTERFACE 欺骗 ✅

- attacker(uid=1000) 发送伪造 SIGNAL: `INTERFACE=org.freedesktop.UDisks2.Manager`, `MEMBER=JobCompleted`
- root 服务 `com.example.PowerManager1` 收到信号并执行了特权操作（自动挂载、备份钩子等）
- 两次伪造信号均被服务端处理
- 关键: bus daemon 不验证 SIGNAL 的 INTERFACE 归属，服务端仅按 INTERFACE+MEMBER+PATH 匹配

## 测试环境

- Docker 容器基于 `jrei/systemd-ubuntu:22.04`（systemd 支持）
- dbus-daemon 1.12.20
- 3 个容器分别验证不同 PoC 场景
- 详细环境搭建见 `dbus-testbed/` 目录

## 文件结构

```
├── b_results/                    # 5 个 PoC 分析报告（pipeline 生成）
│   ├── METHOD_CALL_MEMBER_result.txt
│   ├── METHOD_CALL_DESTINATION_result.txt
│   ├── METHOD_CALL_INTERFACE_result.txt
│   ├── METHOD_CALL_SENDER_result.txt
│   └── SIGNAL_INTERFACE_result.txt
├── dbus-testbed/                 # Docker 测试环境
│   ├── docker-compose.yml
│   ├── start.sh
│   ├── test-results.txt
│   ├── container1-usbcreator/    # PoC 1 & 2
│   ├── container2-interface-acl/ # PoC 3
│   └── container3-p2p-signal/    # PoC 4 & 5
└── report.md                     # 本报告
```
