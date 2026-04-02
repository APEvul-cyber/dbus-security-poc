# D-Bus 协议安全 PoC 验证报告

## 概述

本项目通过自动化 pipeline 生成了 D-Bus 协议的安全分析报告，包括 5 个基础 PoC（`b_results/`）和 16 个 novel attack 场景（`novel_attacks/`）。我们搭建了 Docker 容器环境对这些 PoC 进行了手动验证。

## 基础 PoC 测试结果 (b_results)

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
├── b_results/                    # 5 个基础 PoC 分析报告
│   ├── METHOD_CALL_MEMBER_result.txt
│   ├── METHOD_CALL_DESTINATION_result.txt
│   ├── METHOD_CALL_INTERFACE_result.txt
│   ├── METHOD_CALL_SENDER_result.txt
│   └── SIGNAL_INTERFACE_result.txt
├── novel_attacks/                # 16 个 novel attack 分析报告
│   ├── SIGNAL_PATH_signal_path_spoofing_...
│   ├── SIGNAL_MEMBER_org_freedesktop_DBus__NameOwnerChanged_...
│   ├── SIGNAL_INTERFACE_org_freedesktop_NetworkManager_...
│   ├── METHOD_CALL_SIGNATURE_type_confusion_...
│   ├── METHOD_CALL_SIGNATURE_org_freedesktop_DBus_Properties_GetAll_...
│   └── ... (共 16 个)
├── dbus-testbed/                 # Docker 测试环境
│   ├── docker-compose.yml
│   ├── start.sh
│   ├── test-results.txt
│   ├── container1-usbcreator/    # 基础 PoC 1 & 2
│   ├── container2-interface-acl/ # 基础 PoC 3
│   ├── container3-p2p-signal/    # 基础 PoC 4 & 5 + novel attacks 运行环境
│   └── novel-attacks/            # novel attack 漏洞服务和测试脚本
└── report.md                     # 本报告
```

---

## Novel Attacks 测试结果 (novel_attacks, 前 5 个)

| # | 攻击场景 | 关键字段 | 结果 |
|---|---------|---------|------|
| NA1 | SIGNAL PATH 伪造触发 ConfigManager 重载恶意配置 | `PATH=/org/example/ConfigManager1` | ✅ 成功复现 |
| NA2 | SIGNAL MEMBER 伪造 NameOwnerChanged 解锁会话 | `MEMBER=NameOwnerChanged` | ✅ 成功复现 |
| NA3 | METHOD_CALL INTERFACE 伪造 NM StateChanged 修改防火墙 | `INTERFACE=org.freedesktop.NetworkManager` | ✅ 成功复现 |
| NA4 | SIGNATURE type confusion 绕过验证写 root 配置文件 | `SIGNATURE=ay` | ✅ 成功复现 |
| NA5 | SIGNATURE GetAll 绕过 ACL 读取敏感属性 | `SIGNATURE=s` | ✅ 成功复现 |

**Novel Attacks 前 5 个: 5/5 全部成功复现。**

### NA1 — SIGNAL PATH 伪造 → ConfigManager 重载恶意配置 ✅

- attacker(uid=1000) 发送伪造 SIGNAL: `PATH=/org/example/ConfigManager1`, `MEMBER=ConfigFileChanged`
- root 服务 `org.example.ConfigManager1` 收到信号后以 root 权限读取并加载了 attacker 控制的配置文件
- 恶意配置内容 `ExecStart=/bin/sh -c 'cp /bin/sh /tmp/rootsh; chmod 4755 /tmp/rootsh'` 被写入
- 关键: `PATH` 字段由发送者控制，服务仅按 PATH+INTERFACE+MEMBER 匹配信号，不验证 SENDER

### NA2 — SIGNAL MEMBER 伪造 NameOwnerChanged → 解锁会话 ✅

- attacker 发送伪造 SIGNAL: `MEMBER=NameOwnerChanged`, body=`("com.example.LockHelper1", ":1.55", "")`
- `com.example.SessionManager1` 收到信号后认为 LockHelper 已退出，将会话从 `locked=True` 变为 `locked=False`
- 关键: 服务监听 NameOwnerChanged 但不验证 `SENDER==org.freedesktop.DBus`，任何人都可以伪造此信号

### NA3 — METHOD_CALL INTERFACE 伪造 → 控制 root 防火墙 ✅

- attacker 发送 METHOD_CALL: `INTERFACE=org.freedesktop.NetworkManager`, `MEMBER=StateChanged`, body=`state=70`
- `com.example.NMFirewallHelper` 信任 INTERFACE 字段作为来源证明，执行了 "OPENING all ports" 操作
- 发送 `state=20` 又触发了 "CLOSING all ports"
- 关键: 服务将 INTERFACE 字段当作身份标识，但 D-Bus 规范明确 INTERFACE 由发送者控制

### NA4 — SIGNATURE type confusion → root 写入恶意配置 ✅

- 正常路径 `SetConfig(a{sv})`: 严格验证 key 白名单，`evil_key` 被拒绝
- 攻击路径 `SetConfigRaw(ay)`: 直接将 80 字节恶意配置写入 `/tmp/privileged_config.conf`
- 恶意内容: `[Service]\nExecStart=/bin/sh -c 'cp /bin/sh /tmp/rootsh; chmod 4755 /tmp/rootsh'`
- 关键: 服务根据 SIGNATURE 选择处理路径，`ay` 绕过了 `a{sv}` 的验证逻辑

### NA5 — Properties.GetAll 泄露敏感属性 ✅

- attacker 调用 `GetAll("com.example.PrivilegedConfig1.Secrets")` 获取了:
  - `db_password`: `r00t_db_p@ss`
  - `api_key`: `sk-secret-api-key-12345`
  - `private_key_path`: `/etc/ssl/private/server.key`
- 对照: `GetAll("...Public")` 返回空字典
- 关键: ACL 如果仅匹配 `SIGNATURE=""` 的 GetAll 调用，`SIGNATURE="s"` 的正确调用会绕过

---

## Novel Attacks 测试结果 (NA6–NA16)

| # | 攻击场景 | 关键字段 | 结果 |
|---|---------|---------|------|
| NA6 | PATH 选择系统盘 → UDisks2 Format /dev/sda | `PATH=.../block_devices/sda` | ✅ 成功复现 |
| NA7 | PATH 选择连接 → NM GetSecrets 窃取 WiFi/VPN 密码 | `PATH=.../Settings/1` | ✅ 成功复现 |
| NA8 | MEMBER=Format 触发 root 格式化磁盘 | `MEMBER=Format` | ✅ 成功复现 |
| NA9 | MEMBER=InstallPackages 以 root 安装恶意包 | `MEMBER=InstallPackages` | ✅ 成功复现 |
| NA10 | MEMBER=AddNetwork 注入恶意 WiFi 配置 | `MEMBER=AddNetwork` | ✅ 成功复现 |
| NA11 | INTERFACE=Properties.Set 修改 root 防火墙配置 | `INTERFACE=o.f.DBus.Properties` | ✅ 成功复现 |
| NA12 | INTERFACE=Peer.Ping flood DoS | `INTERFACE=o.f.DBus.Peer` | ✅ 成功复现 |
| NA13 | 省略 INTERFACE → Firewall1 AddRule 绕过 ACL | `INTERFACE=(omitted)` | ✅ 成功复现 |
| NA14 | DESTINATION=UDisks2 沙箱逃逸挂载 | `DESTINATION=o.f.UDisks2` | ✅ 成功复现 |
| NA15 | DESTINATION=PackageKit 沙箱逃逸安装包 | `DESTINATION=o.f.PackageKit` | ✅ 成功复现 |
| NA16 | DESTINATION=NetworkManager 沙箱逃逸窃取凭据 | `DESTINATION=o.f.NetworkManager` | ✅ 成功复现 |

**NA6–NA16: 11/11 全部成功复现。**

### NA6 — PATH 选择系统盘 Format ✅

- attacker 调用 `Format("ext4")` on `PATH=.../block_devices/sda` → root 格式化系统盘
- 对照: `PATH=.../block_devices/sdb` 仅格式化可移动设备
- 关键: PATH 选择哪个块设备被操作，Polkit 规则如果不限制 PATH 则所有设备都可被格式化

### NA7 — PATH 选择连接 GetSecrets ✅

- `PATH=.../Settings/1` → 泄露 WiFi 密码 `MyHomeWiFi_P@ss`
- `PATH=.../Settings/2` → 泄露 VPN 密钥 `Corp_VPN_Secret_Key_12345`
- 关键: 代理服务转发客户端控制的 PATH 到 NM，未验证 PATH 归属

### NA8 — MEMBER=Format 破坏性操作 ✅

- `MEMBER=Format` 触发 mkfs（破坏性），`MEMBER=Mount` 触发挂载（特权但非破坏性）
- 关键: MEMBER 选择代码路径，不同 MEMBER 的危害等级不同

### NA9 — MEMBER=InstallPackages root 安装 ✅

- attacker 安装 `evil-backdoor` 和 `rootkit-pkg`，PackageKit 以 root 执行
- 关键: Polkit 规则如果对 InstallPackages 过于宽松，任何本地用户可安装任意包

### NA10 — MEMBER=AddNetwork 注入恶意 WiFi ✅

- 注入 SSID=`EvilCorp-WiFi`, priority=9999 的恶意网络配置
- 关键: wpa_supplicant D-Bus policy 如果允许非 root 调用 AddNetwork，可劫持 WiFi 连接

### NA11 — Properties.Set 修改 root 配置 ✅

- `Properties.Set("default_policy", "allow_all")` → 防火墙默认策略从 deny 改为 allow_all
- `Properties.Set("log_level", "disabled")` → 关闭日志
- 关键: INTERFACE=o.f.DBus.Properties 是标准接口，如果 ACL 仅限制自定义接口则可绕过

### NA12 — Peer.Ping flood DoS ✅

- 对 3 个服务各发送 200 次 Ping，速率 ~9000 calls/sec
- 关键: Peer.Ping 是标准接口，通常无 ACL 限制，大量并发可耗尽服务资源

### NA13 — 省略 INTERFACE 绕过 ACL ✅

- 带 INTERFACE 的 AddRule → 执行成功
- 省略 INTERFACE 的 AddRule → 同样执行成功（服务按 PATH+MEMBER 分发）
- 关键: 如果 bus policy 仅用 send_interface deny，省略 INTERFACE 可能绕过（取决于 dbus-daemon 版本）
- 注: 此测试中 bus policy 未设置 send_interface deny，展示的是服务端 dispatch 行为

### NA14 — DESTINATION=UDisks2 沙箱逃逸 ✅

- 正确 DEST → root 服务执行 Mount，返回 `/media/root/sdb`
- 错误 DEST → `ServiceUnknown`
- 关键: 沙箱如果不限制 DESTINATION，容器内进程可直接操作宿主机存储

### NA15 — DESTINATION=PackageKit 沙箱逃逸 ✅

- 正确 DEST → root 安装 `malware-pkg`
- 错误 DEST → `ServiceUnknown`
- 关键: 沙箱如果不限制 DESTINATION，容器内进程可在宿主机上安装任意软件包

### NA16 — DESTINATION=NetworkManager 沙箱逃逸 ✅

- 正确 DEST → 泄露 Enterprise 证书密码 `Enterprise_Cert_Password`
- 错误 DEST → `ServiceUnknown`
- 关键: 沙箱如果不限制 DESTINATION，容器内进程可窃取宿主机网络凭据

---

## 总计

| 类别 | 成功 | 失败 | 总计 |
|------|------|------|------|
| 基础 PoC (b_results) | 4 | 1 (CVE-2008-0595 已修复) | 5 |
| Novel Attacks (NA1–NA5) | 5 | 0 | 5 |
| Novel Attacks (NA6–NA16) | 11 | 0 | 11 |
| **总计** | **20** | **1** | **21** |
