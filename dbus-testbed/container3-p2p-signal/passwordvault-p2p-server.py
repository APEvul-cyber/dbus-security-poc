#!/usr/bin/env python3
"""
PoC 4 目标服务: com.example.PasswordVault1 (P2P 模式)

这是一个运行在 Unix domain socket 上的 D-Bus peer-to-peer 服务，
模拟一个密码保险库。它使用 SENDER header 作为客户端身份标识，
但在 P2P 模式下 SENDER 是客户端可控的，不由 bus daemon 验证。

漏洞: 服务信任 SENDER header 作为认证凭据，
      攻击者可以伪造 SENDER 来访问其他客户端的密钥。

使用方法:
  # 启动服务（以 root 运行）
  python3 /usr/local/bin/passwordvault-p2p-server.py

  # 服务监听在 /run/passwordvault1/vault.sock
"""

import socket
import os
import sys
import struct
import logging
import threading
import json

logging.basicConfig(
    level=logging.INFO,
    format='[PasswordVault-P2P] %(asctime)s %(levelname)s: %(message)s'
)
log = logging.getLogger('PasswordVault')

SOCKET_PATH = "/run/passwordvault1/vault.sock"

# 模拟的密钥存储（按 SENDER/client ID 分区）
SECRET_STORES = {
    ":1.42": {
        "bank-account": "s3cr3t_p@ssw0rd_for_bank",
        "email": "em@il_p@ss_victim",
        "ssh-key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...(victim's key)...\n-----END RSA PRIVATE KEY-----",
    },
    ":1.100": {
        "admin-token": "admin_t0ken_super_secret",
        "database": "db_r00t_p@ss",
    },
}


class SimpleDBusP2PServer:
    """
    简化的 D-Bus P2P 服务器
    
    注意: 这是一个简化实现，用于演示 SENDER 信任问题。
    真实的 D-Bus P2P 服务会使用 libdbus 或 GDBus 的 P2P server API。
    这里我们直接解析 D-Bus wire protocol 的关键部分。
    """

    def __init__(self, socket_path):
        self.socket_path = socket_path
        self.running = False

    def start(self):
        # 清理旧 socket
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)

        self.server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_sock.bind(self.socket_path)
        # 允许所有用户连接（模拟真实场景中权限配置不当）
        os.chmod(self.socket_path, 0o777)
        self.server_sock.listen(5)
        self.running = True

        log.info("P2P PasswordVault 服务已启动")
        log.info("监听 socket: %s", self.socket_path)
        log.info("预置的客户端密钥存储:")
        for client_id, secrets in SECRET_STORES.items():
            log.info("  %s: %s", client_id, list(secrets.keys()))

        while self.running:
            try:
                client_sock, _ = self.server_sock.accept()
                log.info("新客户端连接")
                t = threading.Thread(target=self.handle_client, args=(client_sock,))
                t.daemon = True
                t.start()
            except Exception as e:
                if self.running:
                    log.error("接受连接失败: %s", e)

    def handle_client(self, client_sock):
        """处理客户端连接"""
        try:
            # 简化的 D-Bus 认证握手（接受任何认证）
            # 真实 D-Bus 使用 SASL，这里简化处理
            data = client_sock.recv(4096)
            log.info("收到认证数据: %s", data[:100])

            # 发送认证成功响应
            client_sock.sendall(b"OK 1234567890abcdef\r\n")

            # 等待 BEGIN
            data = client_sock.recv(4096)
            log.info("收到: %s", data[:50])

            # 进入消息处理循环
            while True:
                data = client_sock.recv(65536)
                if not data:
                    break

                self.process_message(client_sock, data)

        except Exception as e:
            log.error("客户端处理错误: %s", e)
        finally:
            client_sock.close()
            log.info("客户端断开连接")

    def process_message(self, client_sock, raw_data):
        """
        解析 D-Bus 消息并处理
        
        关键漏洞点: 我们从消息中读取 SENDER header field，
        并直接信任它作为客户端身份。
        在 P2P 模式下，没有 bus daemon 来验证/覆写 SENDER。
        """
        try:
            if len(raw_data) < 16:
                log.warning("消息太短，忽略")
                return

            # 解析 D-Bus 消息头（简化版）
            endian = raw_data[0]
            msg_type = raw_data[1]
            flags = raw_data[2]
            version = raw_data[3]

            if endian == ord('l'):
                byte_order = '<'
            else:
                byte_order = '>'

            body_length = struct.unpack(byte_order + 'I', raw_data[4:8])[0]
            serial = struct.unpack(byte_order + 'I', raw_data[8:12])[0]
            header_fields_length = struct.unpack(byte_order + 'I', raw_data[12:16])[0]

            log.info("收到 D-Bus 消息: type=%d, serial=%d, body_len=%d, header_fields_len=%d",
                     msg_type, serial, body_length, header_fields_length)

            # 解析 header fields（简化: 搜索 SENDER 字段）
            # SENDER field code = 7
            sender = self.extract_sender_from_headers(raw_data[16:16+header_fields_length], byte_order)
            member = self.extract_string_field(raw_data[16:16+header_fields_length], byte_order, 3)  # MEMBER=3

            log.info("  SENDER=%s, MEMBER=%s", sender, member)

            if msg_type == 1:  # METHOD_CALL
                self.handle_method_call(client_sock, sender, member, serial, byte_order)

        except Exception as e:
            log.error("消息解析错误: %s", e)

    def extract_sender_from_headers(self, header_data, byte_order):
        """从 header fields 中提取 SENDER (field code 7)"""
        return self.extract_string_field(header_data, byte_order, 7)

    def extract_string_field(self, header_data, byte_order, target_code):
        """从 header fields 数组中提取指定 code 的字符串字段"""
        pos = 0
        while pos < len(header_data) - 4:
            # 对齐到 8 字节边界
            pos = (pos + 7) & ~7
            if pos >= len(header_data):
                break

            field_code = header_data[pos]
            # 跳过 signature byte
            pos += 1
            if pos >= len(header_data):
                break

            # 读取 variant signature
            sig_len = header_data[pos]
            pos += 1
            if pos + sig_len >= len(header_data):
                break
            sig = header_data[pos:pos+sig_len]
            pos += sig_len + 1  # +1 for null terminator

            if sig == b's' or sig == b'o':
                # 对齐到 4 字节
                pos = (pos + 3) & ~3
                if pos + 4 > len(header_data):
                    break
                str_len = struct.unpack(byte_order + 'I', header_data[pos:pos+4])[0]
                pos += 4
                if pos + str_len > len(header_data):
                    break
                value = header_data[pos:pos+str_len].decode('utf-8', errors='replace')
                pos += str_len + 1  # +1 for null terminator

                if field_code == target_code:
                    return value
            else:
                # 跳过其他类型（简化处理）
                break

        return None

    def handle_method_call(self, client_sock, sender, member, serial, byte_order):
        """
        处理方法调用
        
        漏洞: 使用 SENDER 作为客户端身份标识
        在 P2P 模式下，SENDER 完全由客户端控制！
        """
        if member == "RetrieveSecret":
            log.warning("=" * 60)
            log.warning("RetrieveSecret 被调用!")
            log.warning("SENDER (客户端声称的身份): %s", sender)
            log.warning("注意: 在 P2P 模式下，此 SENDER 值未经验证！")

            # 漏洞点: 直接信任 SENDER 作为身份
            store = SECRET_STORES.get(sender, {})
            if store:
                # 返回该 "客户端" 的所有密钥（简化）
                result = json.dumps(store, indent=2)
                log.warning("返回 SENDER=%s 的密钥存储: %s", sender, list(store.keys()))
                log.warning("如果调用者不是真正的 %s，这就是未授权访问！", sender)
            else:
                result = f"No secrets found for sender {sender}"
                log.info("SENDER=%s 没有关联的密钥存储", sender)

            log.warning("=" * 60)

            # 发送简化的回复（文本格式，非严格 D-Bus wire format）
            reply = f"REPLY serial={serial} sender={sender} data={result}\n"
            try:
                client_sock.sendall(reply.encode())
            except:
                pass

        elif member == "ListClients":
            clients = list(SECRET_STORES.keys())
            log.info("ListClients: %s", clients)
            reply = f"REPLY serial={serial} clients={json.dumps(clients)}\n"
            try:
                client_sock.sendall(reply.encode())
            except:
                pass

        elif member == "Ping":
            try:
                client_sock.sendall(f"REPLY serial={serial} pong\n".encode())
            except:
                pass

        else:
            log.info("未知方法: %s", member)


def main():
    log.info("启动 PasswordVault P2P 服务...")
    log.info("这是一个有漏洞的服务，用于演示 SENDER 伪造攻击")
    log.info("")
    log.info("漏洞说明:")
    log.info("  - 服务运行在 P2P 模式（无 bus daemon）")
    log.info("  - 服务信任 D-Bus 消息中的 SENDER header 作为客户端身份")
    log.info("  - 在 P2P 模式下，SENDER 由客户端自行设置，不受验证")
    log.info("  - 攻击者可以伪造 SENDER=':1.42' 来访问受害者的密钥")
    log.info("")

    server = SimpleDBusP2PServer(SOCKET_PATH)
    try:
        server.start()
    except KeyboardInterrupt:
        log.info("服务关闭")
    finally:
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)


if __name__ == '__main__':
    main()
