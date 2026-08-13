# D-Bus: SIGNAL INTERFACE is not bound to the sender

**Affected:** dbus-daemon / libdbus message fields; lab on Ubuntu-style system bus and P2P.  
**CWE:** CWE-345

uid 1000 can emit a signal with `INTERFACE=org.freedesktop.UDisks2.Manager` and `MEMBER=JobCompleted`. The bus does not check INTERFACE ownership. A root service that matches INTERFACE+MEMBER+PATH runs privileged hooks.

These fields are specified. Attackers set them. Services that trust DESTINATION / SENDER / INTERFACE without their own check are exploitable. That is the CVE.

## Reproduce

`dbus-testbed/container3-p2p-signal/`

**Actual:** privileged path runs for the attacker.  
**Expected:** default policy deny; services must not trust client SENDER/INTERFACE; P2P must not honor peer-supplied SENDER.

## References

- https://github.com/APEvul-cyber/dbus-security-poc/tree/main/signal-interface-spoof
