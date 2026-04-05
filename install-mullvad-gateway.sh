#!/bin/bash
# ==============================================================================
#  MULLVAD DAITA ENFORCED GATEWAY (v22.1)
#
#  CRITICAL BUG FIXES:
#    ISSUE #1 (SSH Lockout): Script ran iptables -F without checking if mullvad
#           was installed. Commands failed, SSH rules were flushed, Pi bricked.
#           FIX: Prerequisite checks before any iptables changes + SSH trap handler.
#
#    BUG 1 (Traffic Leak): iptables -P FORWARD ACCEPT during startup created a
#           15-20 second window where ALL traffic forwarded unprotected to ISP.
#           FIX: Set FORWARD policy to DROP *before* flushing any rules.
#
#    BUG 2 (Traffic Leak): Watchdog did iptables -t nat -F on relay rotation,
#           flushing ALL NAT rules. No MASQUERADE for ~25s = broken clients.
#           FIX: Delete only the old interface's rules, then add new ones.
#
#    BUG 3: No ESTABLISHED,RELATED rule = intermittent drops on existing sessions
#    BUG 4: MSS 1000 too conservative (wastes ~20% throughput at MTU 1280)
#    BUG 5: No conntrack flush on rotation = stale connection hangs
#    BUG 6: No DNS/IPv6 leak prevention at iptables level
#
#  Features: DAITA v2 + Quantum-Resistant + QUIC + CAKE QoS
#  Anti-Repeat: Forces different country on every run
#  Watchdog: Auto-rotates to healthy relay on failure (with ban list)
#
#  Network: Receives traffic on eth0 from pfSense/router gateway rule
#           Exits via wg-mullvad interface to internet
# ==============================================================================

set -euo pipefail

# --- CONFIGURATION ---
LAN_IF="eth0"                               # Interface facing your LAN/router
ALLOWED_COUNTRIES=("nl" "ch" "se" "de" "us")
BAN_FILE="/var/log/mullvad_banlist.log"
LAST_USED_FILE="/var/tmp/mullvad_last_gw"
LOG_FILE="/var/log/mullvad-gateway.log"
CAKE_BW="500mbit"
# MTU 1280 - 20 (IP header) - 20 (TCP header) = 1240
# Slightly conservative for QUIC+Quantum overhead
MSS_CLAMP=1220

# ==============================================================================
# ISSUE #1 FIX: Prerequisite checks BEFORE touching iptables
#
# Original script ran iptables -F immediately, flushing any SSH allow rules.
# If mullvad wasn't installed, commands failed, SSH was locked out, and the
# Pi was bricked (no console on headless Pi 3B).
#
# Fix: Check everything is installed first. If anything is missing, abort
# without changing any firewall rules. Also install a trap handler that
# restores SSH access if the script fails at any point.
# ==============================================================================

echo ""
echo "============================================================"
echo "  MULLVAD GATEWAY v22.1 — Pre-flight checks"
echo "============================================================"

PREFLIGHT_FAIL=0

# Check: running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "FAIL: Must run as root (sudo)"
    exit 1
fi

# Check: mullvad CLI installed
if ! command -v mullvad &>/dev/null; then
    echo "FAIL: 'mullvad' command not found."
    echo "      Install Mullvad first:"
    echo "      curl -fsSLo /usr/share/keyrings/mullvad-keyring.asc https://repository.mullvad.net/deb/mullvad-keyring.asc"
    echo "      echo \"deb [signed-by=/usr/share/keyrings/mullvad-keyring.asc arch=\$(dpkg --print-architecture)] https://repository.mullvad.net/deb/stable \$(lsb_release -cs) main\" | sudo tee /etc/apt/sources.list.d/mullvad.list"
    echo "      sudo apt update && sudo apt install mullvad-vpn -y"
    PREFLIGHT_FAIL=1
fi

# Check: mullvad daemon service exists
if ! systemctl list-unit-files mullvad-daemon.service &>/dev/null; then
    echo "FAIL: mullvad-daemon.service not found."
    PREFLIGHT_FAIL=1
fi

# Check: mullvad account logged in
if command -v mullvad &>/dev/null; then
    if ! mullvad account get &>/dev/null; then
        echo "FAIL: Not logged in to Mullvad."
        echo "      Run: mullvad account login YOUR_ACCOUNT_NUMBER"
        PREFLIGHT_FAIL=1
    fi
fi

# Check: iptables available
if ! command -v iptables &>/dev/null; then
    echo "FAIL: 'iptables' not found. Install: apt install iptables"
    PREFLIGHT_FAIL=1
fi

# Check: network interface exists
if ! ip link show "$LAN_IF" &>/dev/null; then
    echo "FAIL: Interface '$LAN_IF' not found."
    echo "      Available interfaces:"
    ip -br link show | grep -v lo
    echo "      Edit LAN_IF at the top of this script."
    PREFLIGHT_FAIL=1
fi

# Check: RAM (Pi 3B = 1GB, DAITA+Quantum needs ~800MB)
TOTAL_RAM_MB=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo)
if [ "$TOTAL_RAM_MB" -lt 1500 ]; then
    echo "WARN: Only ${TOTAL_RAM_MB}MB RAM detected."
    echo "      DAITA + Quantum + QUIC needs ~800MB."
    echo "      On Pi 3B (1GB), you may hit OOM and lose SSH."
    echo "      Consider disabling DAITA: edit connect_mullvad()"
    # Don't fail — just warn
fi

# Abort if any prerequisite failed
if [ "$PREFLIGHT_FAIL" -ne 0 ]; then
    echo ""
    echo "ABORTED: Fix the above issues and re-run."
    echo "         No firewall rules were changed. SSH is safe."
    exit 1
fi

echo "PASS: All prerequisites met."

# ==============================================================================
# SSH SAFETY TRAP: If the script fails at ANY point after this, restore SSH.
# This prevents the lockout described in issue #1.
# ==============================================================================
restore_ssh() {
    echo "[$(date)] TRAP: Script failed. Restoring SSH access..." >&2
    # Ensure INPUT allows SSH regardless of policy
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -A INPUT -i "$LAN_IF" -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    echo "[$(date)] TRAP: SSH access restored. Check firewall manually." >&2
}
trap restore_ssh ERR

# --- LOGGING ---
touch "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1
echo ""
echo "============================================================"
echo "[$(date)] MULLVAD GATEWAY v22.1 — Starting"
echo "============================================================"

# --- FUNCTIONS ---

clean_ban_list() {
    if [ -f "$BAN_FILE" ]; then
        local NOW
        NOW=$(date +%s)
        local EXPIRY=$((NOW - 28800))  # 8 hour ban window
        awk -v expiry="$EXPIRY" '$1 > expiry' "$BAN_FILE" > "${BAN_FILE}.tmp" \
            && mv "${BAN_FILE}.tmp" "$BAN_FILE"
    fi
}

get_valid_country() {
    clean_ban_list

    # Get non-banned countries
    local AVAILABLE=()
    for c in "${ALLOWED_COUNTRIES[@]}"; do
        if ! grep -q " $c$" "$BAN_FILE" 2>/dev/null; then
            AVAILABLE+=("$c")
        fi
    done

    # Safety: if all banned, reset
    if [ ${#AVAILABLE[@]} -eq 0 ]; then
        echo "[$(date)] All regions banned. Resetting list." >&2
        true > "$BAN_FILE"
        AVAILABLE=("${ALLOWED_COUNTRIES[@]}")
    fi

    # Anti-repeat: exclude last used country
    local LAST_USED=""
    [ -f "$LAST_USED_FILE" ] && LAST_USED=$(cat "$LAST_USED_FILE")
    local CANDIDATES=()
    for c in "${AVAILABLE[@]}"; do
        [ "$c" != "$LAST_USED" ] && CANDIDATES+=("$c")
    done
    [ ${#CANDIDATES[@]} -eq 0 ] && CANDIDATES=("${AVAILABLE[@]}")

    # Pick random
    local SELECTED=${CANDIDATES[$((RANDOM % ${#CANDIDATES[@]}))]}
    echo "$SELECTED" > "$LAST_USED_FILE"
    echo "$SELECTED"
}

# ==============================================================================
# BUG 1 FIX: Set DROP policy BEFORE flushing rules.
#
# The original script did:
#   iptables -F                    <- flush all rules
#   iptables -P FORWARD ACCEPT     <- set policy to ACCEPT
#   [... 15-20 seconds of daemon restart + handshake ...]
#
# During that window, ALL traffic was forwarded directly to the ISP.
#
# The fix: set DROP first, then flush. Traffic is blocked by default
# until tunnel rules are explicitly added after the connection is up.
# ==============================================================================
setup_firewall_lockdown() {
    echo "[$(date)] Setting firewall lockdown (DROP all forwards)..."

    # DROP policy FIRST — this is the critical fix for BUG 1
    iptables -P FORWARD DROP
    iptables -P INPUT DROP
    iptables -P OUTPUT ACCEPT

    # Now safe to flush — default policy is already DROP
    iptables -F
    iptables -t nat -F
    iptables -t mangle -F

    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT

    # BUG 3 FIX: Allow established/related connections
    # Without this, existing sessions drop during rule reload
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow management access (SSH + ICMP)
    iptables -A INPUT -i "$LAN_IF" -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -i "$LAN_IF" -p icmp -j ACCEPT

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    # BUG 6 FIX: Disable IPv6 to prevent leaks
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null

    echo "[$(date)] Firewall locked down. No traffic forwarded until tunnel is up."
}

apply_tunnel_rules() {
    local WG_IF=$1
    echo "[$(date)] Applying tunnel rules for: $WG_IF"

    # Set MTU
    ip link set dev "$WG_IF" mtu 1280

    # Allow forwarding ONLY through the tunnel interface
    iptables -A FORWARD -i "$LAN_IF" -o "$WG_IF" -j ACCEPT
    # Return traffic handled by ESTABLISHED,RELATED rule above

    # NAT: Masquerade outbound traffic
    iptables -t nat -A POSTROUTING -o "$WG_IF" -j MASQUERADE

    # BUG 4 FIX: MSS 1220 instead of 1000 (recovers ~20% throughput)
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
        -j TCPMSS --set-mss $MSS_CLAMP

    # BUG 6 FIX: Block DNS that tries to bypass the tunnel
    iptables -A FORWARD -i "$LAN_IF" -o "$LAN_IF" -p udp --dport 53 -j DROP
    iptables -A FORWARD -i "$LAN_IF" -o "$LAN_IF" -p tcp --dport 53 -j DROP

    # CAKE traffic shaping
    tc qdisc del dev "$LAN_IF" root 2>/dev/null || true
    tc qdisc add dev "$LAN_IF" root cake bandwidth $CAKE_BW nat wash ack-filter

    echo "[$(date)] Tunnel rules active. MSS=$MSS_CLAMP, CAKE=$CAKE_BW"
}

connect_mullvad() {
    local COUNTRY=$1
    echo "[$(date)] Connecting to ${COUNTRY^^}..."

    mullvad disconnect 2>/dev/null || true

    # Configure Mullvad — CLI syntax for 2025.14+
    # Ref: https://mullvad.net/en/help/cli-command-wg
    mullvad relay set location "$COUNTRY"
    mullvad obfuscation set mode quic
    mullvad tunnel set quantum-resistant on
    mullvad tunnel set daita on
    mullvad lan set allow

    # Cold boot: restart daemon for clean bind with heavy crypto stack
    echo "[$(date)] Cold booting daemon..."
    systemctl restart mullvad-daemon
    sleep 10

    mullvad connect

    # Wait for WireGuard interface
    local MAX_RETRIES=45
    local COUNT=0
    local WG_IF=""
    while [ $COUNT -lt $MAX_RETRIES ]; do
        WG_IF=$(ip -br link show | grep -oE 'wg[0-9]?-mullvad' | head -1)
        if [ -n "$WG_IF" ]; then
            echo "[$(date)] Interface created: $WG_IF"
            echo "$WG_IF" > /var/tmp/mullvad_current_if
            return 0
        fi
        sleep 1
        ((COUNT++))
    done

    echo "[$(date)] CRITICAL: Handshake failed after ${MAX_RETRIES}s"
    return 1
}

# --- MAIN ---

# 1. Kill existing watchdog
pkill -f "mullvad_watchdog_v22" 2>/dev/null || true
sleep 1

# 2. Disable Energy Efficient Ethernet (reduces latency jitter on Pi)
ethtool --set-eee "$LAN_IF" eee off 2>/dev/null || true

# 3. LOCKDOWN FIRST (BUG 1 FIX) — no traffic leaks during startup
setup_firewall_lockdown

# 4. Connect
TARGET=$(get_valid_country)
echo "[$(date)] Target: ${TARGET^^}"

if ! connect_mullvad "$TARGET"; then
    echo "[$(date)] FAILED: Trying without DAITA..."
    mullvad tunnel set daita off
    if ! connect_mullvad "$TARGET"; then
        echo "[$(date)] CRITICAL: All attempts failed. Gateway locked down."
        exit 1
    fi
fi

# 5. Apply tunnel rules (opens forwarding through tunnel only)
WG_IF=$(cat /var/tmp/mullvad_current_if)
apply_tunnel_rules "$WG_IF"

# 6. Verification
sleep 3
STATUS=$(mullvad status 2>/dev/null | head -n 1 || echo "Unknown")
IP=$(curl -s --connect-timeout 5 https://am.i.mullvad.net/ip || echo "Unknown")
OBF=$(mullvad obfuscation get 2>/dev/null | awk '/mode:/ {print $NF}' || echo "unknown")

echo ""
echo "================== STATUS REPORT =================="
echo "  STATUS:      $STATUS"
echo "  PUBLIC IP:   $IP"
echo "  INTERFACE:   $WG_IF"
echo "  OBFUSCATION: $OBF"
echo "  MSS CLAMP:   $MSS_CLAMP"
echo "  QUEUE:       CAKE ($CAKE_BW)"
echo "  FWD POLICY:  DROP (tunnel-only)"
echo "  IPv6:        Disabled (leak prevention)"
echo "==================================================="

# ==============================================================================
# 7. SMART WATCHDOG (BUG 2 FIX)
#
# The original watchdog did: iptables -t nat -F (flush ALL NAT rules)
# This killed MASQUERADE for ~25 seconds during relay rotation.
#
# The fix: Delete only the old interface's rules with iptables -D,
# then add new rules with iptables -A. The ESTABLISHED,RELATED rule
# keeps existing sessions alive through the transition.
# ==============================================================================
(
exec -a mullvad_watchdog_v22 bash -c '
LAN_IF="'"$LAN_IF"'"
MSS_CLAMP='"$MSS_CLAMP"'
CAKE_BW="'"$CAKE_BW"'"
ALLOWED_COUNTRIES=('"$(printf '"%s" ' "${ALLOWED_COUNTRIES[@]}")"')
BAN_FILE="'"$BAN_FILE"'"
LAST_USED_FILE="'"$LAST_USED_FILE"'"
LOG_FILE="'"$LOG_FILE"'"

FAIL_COUNT=0
THRESHOLD=3
CURRENT_IF=$(cat /var/tmp/mullvad_current_if 2>/dev/null || echo "")

echo "[$(date)] Watchdog v22 active. Interface: $CURRENT_IF" >> "$LOG_FILE"

while true; do
    sleep 10

    if ! ping -c 1 -W 3 1.1.1.1 > /dev/null 2>&1; then
        ((FAIL_COUNT++))
        echo "[$(date)] Packet loss ($FAIL_COUNT/$THRESHOLD)" >> "$LOG_FILE"

        if [ $FAIL_COUNT -ge $THRESHOLD ]; then
            echo "[$(date)] CONNECTION DEAD — rotating relay" >> "$LOG_FILE"

            # Ban current country
            CURRENT_COUNTRY=$(cat "$LAST_USED_FILE" 2>/dev/null || echo "")
            [ -n "$CURRENT_COUNTRY" ] && echo "$(date +%s) $CURRENT_COUNTRY" >> "$BAN_FILE"

            # BUG 2 FIX: Remove ONLY the old interface rules (no flush)
            OLD_IF="$CURRENT_IF"
            if [ -n "$OLD_IF" ]; then
                iptables -D FORWARD -i "$LAN_IF" -o "$OLD_IF" -j ACCEPT 2>/dev/null || true
                iptables -t nat -D POSTROUTING -o "$OLD_IF" -j MASQUERADE 2>/dev/null || true
                # BUG 5 FIX: Flush conntrack to clear stale entries
                conntrack -F 2>/dev/null || true
            fi

            # Pick new country (with ban + anti-repeat)
            NOW=$(date +%s); EXPIRY=$((NOW - 28800))
            [ -f "$BAN_FILE" ] && {
                awk -v expiry="$EXPIRY" "\$1 > expiry" "$BAN_FILE" > "${BAN_FILE}.tmp"
                mv "${BAN_FILE}.tmp" "$BAN_FILE"
            }
            AVAILABLE=()
            for c in "${ALLOWED_COUNTRIES[@]}"; do
                grep -q " $c$" "$BAN_FILE" 2>/dev/null || AVAILABLE+=("$c")
            done
            [ ${#AVAILABLE[@]} -eq 0 ] && { true > "$BAN_FILE"; AVAILABLE=("${ALLOWED_COUNTRIES[@]}"); }
            NEW_COUNTRY=${AVAILABLE[$((RANDOM % ${#AVAILABLE[@]}))]}

            echo "[$(date)] Switching to: ${NEW_COUNTRY^^}" >> "$LOG_FILE"

            mullvad disconnect 2>/dev/null || true
            mullvad relay set location "$NEW_COUNTRY"
            mullvad obfuscation set mode quic
            mullvad tunnel set quantum-resistant on
            mullvad tunnel set daita on
            systemctl restart mullvad-daemon
            sleep 10
            mullvad connect
            sleep 8

            NEW_IF=$(ip -br link show | grep -oE "wg[0-9]?-mullvad" | head -1)
            if [ -n "$NEW_IF" ]; then
                # Apply new rules (surgical add, not flush)
                ip link set dev "$NEW_IF" mtu 1280
                iptables -A FORWARD -i "$LAN_IF" -o "$NEW_IF" -j ACCEPT
                iptables -t nat -A POSTROUTING -o "$NEW_IF" -j MASQUERADE

                # Re-add MSS clamp if needed (check prevents duplicates)
                iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN \
                    -j TCPMSS --set-mss $MSS_CLAMP 2>/dev/null || \
                    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
                    -j TCPMSS --set-mss $MSS_CLAMP

                # Refresh CAKE
                tc qdisc del dev "$LAN_IF" root 2>/dev/null || true
                tc qdisc add dev "$LAN_IF" root cake bandwidth $CAKE_BW nat wash ack-filter

                echo "$NEW_IF" > /var/tmp/mullvad_current_if
                echo "$NEW_COUNTRY" > "$LAST_USED_FILE"
                CURRENT_IF="$NEW_IF"
                FAIL_COUNT=0
                echo "[$(date)] Recovered on ${NEW_COUNTRY^^} via $NEW_IF" >> "$LOG_FILE"
            else
                echo "[$(date)] CRITICAL: Interface creation failed" >> "$LOG_FILE"
            fi
        fi
    else
        FAIL_COUNT=0
    fi
done
'
) &
disown

echo "[$(date)] Watchdog launched (PID: $!)"

# Clear the SSH safety trap — script completed successfully
trap - ERR
echo "[$(date)] Gateway ready."
