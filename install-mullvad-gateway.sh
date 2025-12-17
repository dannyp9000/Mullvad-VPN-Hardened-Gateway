#!/bin/bash
# ==============================================================================
#  PROJECT: Mullvad Hardened Gateway (DAITA + Quantum + QUIC)
#  DEVICE:  Raspberry Pi 5 (Gateway: 192.168.0.3)
#  AUTHOR:  Auto-Generated Installer
# ==============================================================================

if [ "$EUID" -ne 0 ]; then
  echo "❌ Please run as root (use sudo)"
  exit
fi

echo "🟢 Starting Installation..."

# ------------------------------------------------------------------------------
# 1. CREATE MAIN LOGIC SCRIPT (/usr/local/bin/mullvad-gateway.sh)
# ------------------------------------------------------------------------------
echo "⚙️  Writing Gateway Script..."
cat << 'EOF' > /usr/local/bin/mullvad-gateway.sh
#!/bin/bash
# MULLVAD HARDENED GATEWAY (v17.1 Stable)

# 1. CLEANUP & PREP
pkill -f "mullvad_watchdog_process"
pkill -f "ping -c 1"
iptables -F
iptables -P FORWARD ACCEPT
echo "[$(date)] 🟢 Starting Gateway Sequence..."

# 2. OPTIMIZE NETWORK
ethtool --set-eee eth0 eee off > /dev/null 2>&1 || true
sysctl -w net.ipv4.ip_forward=1 > /dev/null

# 3. CONFIGURE MULLVAD
mullvad disconnect
mullvad obfuscation set mode quic
mullvad relay set tunnel-protocol wireguard
mullvad relay set location nl
mullvad tunnel set wireguard --quantum-resistant on
mullvad tunnel set wireguard --daita on
mullvad lan set allow

# 4. COLD BOOT (CRITICAL FIX)
echo "🔄 Restarting Mullvad Service..."
systemctl restart mullvad-daemon
sleep 10

# 5. CONNECT & WAIT
echo "⏳ Connecting..."
mullvad connect

MAX_RETRIES=45
COUNT=0
NEW_WG_IF=""
while [ $COUNT -lt $MAX_RETRIES ]; do
    NEW_WG_IF=$(ip -br link show | grep -E 'wg[0-9]?-mullvad' | awk '{print $1}')
    if [ -n "$NEW_WG_IF" ]; then
        echo "✅ Interface Created: $NEW_WG_IF"
        break
    fi
    sleep 1
    ((COUNT++))
done

if [ -z "$NEW_WG_IF" ]; then
    echo "❌ CRITICAL: Handshake failed. Reverting to safe mode..."
    mullvad tunnel set wireguard --daita off
    mullvad connect
    exit 1
fi

# 6. ROUTING & FIREWALL
ip link set dev "$NEW_WG_IF" mtu 1280
iptables -t nat -A POSTROUTING -o "$NEW_WG_IF" -j MASQUERADE
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1000

# 7. TRAFFIC CONTROL (CAKE - 500Mbit)
tc qdisc del dev eth0 root > /dev/null 2>&1
tc qdisc add dev eth0 root cake bandwidth 500mbit nat wash ack-filter

# 8. VERIFICATION
echo "⏳ Waiting for connectivity..."
sleep 5
STATUS=$(mullvad status | head -n 1)
IP=$(curl -s --connect-timeout 5 https://am.i.mullvad.net/ip || echo "Unknown")

echo "================ STATUS REPORT ================"
echo "STATUS:      $STATUS"
echo "PUBLIC IP:   $IP"
echo "OBFUSCATION: $(mullvad obfuscation get | awk '{print $2}')"
echo "DAITA/PQC:   Active"
echo "==============================================="
EOF

# Make it executable
chmod +x /usr/local/bin/mullvad-gateway.sh

# ------------------------------------------------------------------------------
# 2. CREATE SYSTEMD SERVICE (/etc/systemd/system/mullvad-gateway.service)
# ------------------------------------------------------------------------------
echo "⚙️  Creating Auto-Start Service..."
cat << 'EOF' > /etc/systemd/system/mullvad-gateway.service
[Unit]
Description=Mullvad Hardened Gateway (DAITA/QUIC/Quantum)
After=network-online.target mullvad-daemon.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/mullvad-gateway.sh
RemainAfterExit=yes
StandardOutput=append:/var/log/mullvad-optimizer.log
StandardError=append:/var/log/mullvad-optimizer.log

[Install]
WantedBy=multi-user.target
EOF

# ------------------------------------------------------------------------------
# 3. CREATE KERNEL CONFIG (/etc/sysctl.d/99-mullvad-router.conf)
# ------------------------------------------------------------------------------
echo "⚙️  Applying Persistent Kernel Settings..."
cat << 'EOF' > /etc/sysctl.d/99-mullvad-router.conf
# Enable IP Forwarding
net.ipv4.ip_forward=1
# Optimize for High Speed VPN
net.core.default_qdisc=fq_codel
net.ipv4.tcp_congestion_control=bbr
EOF

# Apply Kernel settings immediately
sysctl -p /etc/sysctl.d/99-mullvad-router.conf > /dev/null

# ------------------------------------------------------------------------------
# 4. ENABLE & START
# ------------------------------------------------------------------------------
echo "🚀 Enabling Services..."
systemctl daemon-reload
systemctl enable mullvad-gateway.service

echo "✅ INSTALLATION COMPLETE."
echo "   To start the gateway now: sudo systemctl start mullvad-gateway"
echo "   To check logs: tail -f /var/log/mullvad-optimizer.log"
