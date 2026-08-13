# dbus-security-poc

D-Bus fields attackers set. USBCreator Image is also CVE-2013-1060. Omit-INTERFACE (CVE-2008-0595) did not reproduce on dbus-daemon 1.12.20.

| Dir | Issue |
|---|---|
| `destination-routing` | DESTINATION routes an unprivileged message to a root service |
| `sender-spoof-p2p` | P2P D-Bus trusts client-supplied SENDER |
| `signal-interface-spoof` | SIGNAL INTERFACE is not bound to the sender |
