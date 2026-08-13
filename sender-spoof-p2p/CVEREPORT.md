# D-Bus: P2P D-Bus trusts client-supplied SENDER

**Affected:** dbus-daemon / libdbus message fields; lab on Ubuntu-style system bus and P2P.  
**CWE:** CWE-290

On a P2P Unix socket there is no dbus-daemon to overwrite SENDER. The server reads `SENDER=:1.42` and treats it as the victim. Lab returns that user's secrets (and `:1.100` admin tokens).

These fields are specified. Attackers set them. Services that trust DESTINATION / SENDER / INTERFACE without their own check are exploitable. That is the CVE.

## Reproduce

`dbus-testbed/container3-p2p-signal/poc4_sender_spoof.py`

**Actual:** privileged path runs for the attacker.  
**Expected:** default policy deny; services must not trust client SENDER/INTERFACE; P2P must not honor peer-supplied SENDER.

## References

- https://github.com/APEvul-cyber/dbus-security-poc/tree/main/sender-spoof-p2p
