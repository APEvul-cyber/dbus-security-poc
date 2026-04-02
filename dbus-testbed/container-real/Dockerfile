FROM jrei/systemd-ubuntu:22.04

LABEL description="Real D-Bus service attack surface testing"

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    dbus dbus-x11 \
    udisks2 \
    packagekit \
    network-manager \
    bluez \
    avahi-daemon \
    policykit-1 \
    accountsservice \
    colord \
    python3 python3-dbus python3-gi gir1.2-glib-2.0 \
    strace vim less procps iproute2 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash attacker && echo "attacker:attacker" | chpasswd

RUN systemctl enable dbus && \
    systemctl enable udisks2 || true && \
    systemctl enable NetworkManager || true && \
    systemctl enable packagekit || true && \
    systemctl enable bluetooth || true && \
    systemctl enable avahi-daemon || true && \
    systemctl enable accounts-daemon || true && \
    systemctl enable colord || true

WORKDIR /opt/test
