# D-Bus: DESTINATION routes an unprivileged message to a root service

**Affected:** dbus-daemon / libdbus message fields; lab on Ubuntu-style system bus and P2P.  
**CWE:** CWE-863

A client sets `DESTINATION=com.ubuntu.USBCreator` (or any privileged well-known name). The bus delivers the method call to that service. The service runs as root and performs the member (`Image`). Attackers pick DESTINATION; the bus does not ask whether this uid may talk to that name unless a policy rule says so. Lab: USBCreator `Image` copies `/etc/shadow` for uid 1000.

These fields are specified. Attackers set them. Services that trust DESTINATION / SENDER / INTERFACE without their own check are exploitable. That is the CVE.

## Reproduce

`dbus-testbed/container1-usbcreator/`

**Actual:** privileged path runs for the attacker.  
**Expected:** default policy deny; services must not trust client SENDER/INTERFACE; P2P must not honor peer-supplied SENDER.

## References

- https://github.com/APEvul-cyber/dbus-security-poc/tree/main/destination-routing
