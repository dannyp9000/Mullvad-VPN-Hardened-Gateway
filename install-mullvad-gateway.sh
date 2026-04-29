#!/bin/bash
# ==============================================================================
#   MULLVAD HARDENED GATEWAY — DAITA + Quantum + QUIC (v25.0)
#   Tested: Mullvad 2026.1 / Debian 13 (Trixie) / Pi 5 4GB / Proxmox VM
#
#   Usage:
#     sudo bash install-mullvad-gateway.sh
#     sudo LAN_IF=ens19 bash install-mullvad-gateway.sh
#     sudo LAN_IF=eth0 WG_MTU=1280 MSS_CLAMP=1000 bash install-mullvad-gateway.sh
#
#   v25 changes (output polish on top of v24 fixes):
#     - Emoji-prefixed status messages matching README style
#     - Verbose status report with relay name, location, tunnel IPs
#     - Account expiry shown in pre-flight
#     - MSS / MTU annotated with safety descriptor
#     - Obfuscation shown as "name (DESCRIPTION)" form
#     - Watchdog log entries get connection-drop / recovery emoji
#     - Cleaner section dividers
#
#   v24 fixes:
#     - Strict 16-digit Mullvad account regex (no false-positive on 4-digit nums)
#     - LAN_IF detection refuses to guess on multi-iface systems
#     - set -uo pipefail + explicit fail() / restore_ssh on signals
#     - restore_ssh() flushes filter, nat, mangle, ip6tables
#     - mullvad lockdown-mode as host kill-switch
#     - mullvad status --json parsing (text fallback case-ordered correctly)
#     - mullvad connect --wait replaces manual poll loops
#     - Watchdog: DAITA-off fallback + exponential backoff
#     - WG_MTU / MSS_CLAMP env-overridable with stacked-WG defaults
#     - MSS clamp on FORWARD AND OUTPUT
#     - Keyring download error-checked, apt errors surfaced
#     - ethtool guarded for virtio NICs
#     - Watchdog uses stable tag + pidfile (no version-pinned pkill)
# ==============================================================================

set -uo pipefail

# --- CONFIG ---
ALLOWED_COUNTRIES=("nl" "ch" "us" "de" "se")
BAN_FILE="/var/log/mullvad_banlist.log"
LAST_USED_FILE="/var/tmp/mullvad_last_gw"
LOG_FILE="/var/log/mullvad-optimizer.log"
WATCHDOG_PIDFILE="/var/run/mullvad-gateway-watchdog.pid"
WATCHDOG_TAG="mullvad_gateway_watchdog"
SCRIPT_VERSION="25.0"

# Tunables (env-overridable). Defaults sized for stacked WG-in-WG (Proton -> Mullvad)
# where outer overhead eats roughly 80 + 40 = 120 bytes off a 1500 path MTU.
CAKE_BW="${CAKE_BW:-500mbit}"
WG_MTU="${WG_MTU:-1280}"          # WireGuard floor per Mullvad docs.
MSS_CLAMP="${MSS_CLAMP:-1100}"    # Conservative for stacked tunnels.
ENABLE_LOCKDOWN="${ENABLE_LOCKDOWN:-1}"

# --- DESCRIPTOR HELPERS ---
mss_descriptor() {
    local v="$1"
    if   [ "$v" -le 1000 ]; then echo "Ultra-Conservative"
    elif [ "$v" -le 1150 ]; then echo "Safe"
    elif [ "$v" -le 1300 ]; then echo "Standard"
    else                          echo "Aggressive"
    fi
}

mtu_descriptor() {
    local v="$1"
    if   [ "$v" -lt 1280 ]; then echo "Below WG floor!"
    elif [ "$v" -eq 1280 ]; then echo "WireGuard Standard"
    elif [ "$v" -le 1420 ]; then echo "Tuned"
    else                          echo "Aggressive"
    fi
}

obf_descriptor() {
    case "$1" in
        quic)        echo "QUIC over UDP" ;;
        shadowsocks) echo "Shadowsocks" ;;
        udp2tcp)     echo "UDP-over-TCP" ;;
        lwo)         echo "Lightweight Obfuscation" ;;
        none|"")     echo "None" ;;
        *)           echo "$1" ;;
    esac
}

# --- LAN_IF DETECTION ---
detect_lan_if() {
    if [ -n "${LAN_IF:-}" ]; then return 0; fi

    local IFACES
    mapfile -t IFACES < <(ip -br link show 2>/dev/null \
        | awk '$1 != "lo" && $2 == "UP" {print $1}')

    if [ "${#IFACES[@]}" -eq 1 ]; then
        LAN_IF="${IFACES[0]}"
        echo "🔧 Auto-detected LAN_IF=$LAN_IF (sole UP interface)"
        return 0
    fi
    if [ "${#IFACES[@]}" -eq 0 ]; then
        echo "❌ FAIL: No UP interfaces found"
        return 1
    fi
    echo "❌ FAIL: Multiple UP interfaces detected — refusing to guess LAN_IF"
    echo "   Available interfaces:"
    ip -br link show | awk '$1 != "lo" && $2 == "UP" {print "     " $1}'
    echo ""
    echo "   Set LAN_IF explicitly. Example:"
    echo "     sudo LAN_IF=ens19 bash install-mullvad-gateway.sh"
    return 1
}

# --- BANNER ---
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  🔒 MULLVAD HARDENED GATEWAY  v${SCRIPT_VERSION}"
echo "      DAITA + Quantum-Resistant + QUIC"
echo "══════════════════════════════════════════════════════════════"

[ "$(id -u)" -ne 0 ] && { echo "❌ FAIL: Must run as root"; exit 1; }

# --- INSTALL DEPENDENCIES ---
NEEDED_PKGS=()
for pkg in curl iptables conntrack ethtool iproute2; do
    case "$pkg" in
        iproute2) command -v ip      &>/dev/null || NEEDED_PKGS+=("iproute2") ;;
        ethtool)  command -v ethtool &>/dev/null || NEEDED_PKGS+=("ethtool")  ;;
        *)        command -v "$pkg"  &>/dev/null || NEEDED_PKGS+=("$pkg")     ;;
    esac
done
if [ "${#NEEDED_PKGS[@]}" -gt 0 ]; then
    echo "📦 Installing: ${NEEDED_PKGS[*]}"
    apt-get update -qq          || { echo "❌ FAIL: apt-get update"; exit 1; }
    apt-get install -y "${NEEDED_PKGS[@]}" || { echo "❌ FAIL: package install"; exit 1; }
fi

if ! command -v mullvad &>/dev/null; then
    echo "📦 Mullvad not found — installing..."
    if ! curl -fsSLo /usr/share/keyrings/mullvad-keyring.asc \
            https://repository.mullvad.net/deb/mullvad-keyring.asc; then
        echo "❌ FAIL: Could not download Mullvad keyring"
        exit 1
    fi
    ARCH="$(dpkg --print-architecture)"
    echo "deb [signed-by=/usr/share/keyrings/mullvad-keyring.asc arch=${ARCH}] https://repository.mullvad.net/deb/stable stable main" \
        > /etc/apt/sources.list.d/mullvad.list
    apt-get update -qq      || { echo "❌ FAIL: apt-get update after Mullvad repo"; exit 1; }
    apt-get install -y mullvad-vpn || { echo "❌ FAIL: Mullvad install"; exit 1; }
    echo "✅ Mullvad installed"
    sleep 3
fi

# --- INTERFACE ---
detect_lan_if || exit 1
if ! ip link show "$LAN_IF" &>/dev/null; then
    echo "❌ FAIL: Interface '$LAN_IF' not found"
    ip -br link show | grep -v lo
    exit 1
fi
echo "✅ Interface: $LAN_IF"

TOTAL_RAM_MB=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo)
[ "$TOTAL_RAM_MB" -lt 1500 ] && echo "⚠️  WARN: ${TOTAL_RAM_MB}MB RAM — DAITA may OOM"

# --- DAEMON READY ---
systemctl start mullvad-daemon 2>/dev/null || true

echo -n "⏳ Waiting for daemon"
TRIES=0
while [ $TRIES -lt 30 ]; do
    if mullvad status &>/dev/null; then
        echo " ok"
        break
    fi
    echo -n "."
    sleep 1
    TRIES=$((TRIES + 1))
done
if [ $TRIES -ge 30 ]; then
    echo ""
    echo "❌ FAIL: Mullvad daemon did not become ready in 30s"
    echo "   Check: systemctl status mullvad-daemon"
    exit 1
fi

mullvad disconnect 2>/dev/null || true
sleep 2

# --- LOGIN CHECK (strict 16-digit account format) ---
LOGGED_IN=false

if [ -f /etc/mullvad-vpn/device.json ]; then
    LOGGED_IN=true
fi

if ! $LOGGED_IN; then
    ACCT_OUT="$(mullvad account get 2>&1 || true)"
    if echo "$ACCT_OUT" | grep -qE '([0-9]{16}|([0-9]{4}[[:space:]]+){3}[0-9]{4})'; then
        LOGGED_IN=true
    fi
fi

if ! $LOGGED_IN; then
    if mullvad status --json 2>/dev/null | grep -q '"device"'; then
        LOGGED_IN=true
    fi
fi

if ! $LOGGED_IN; then
    echo ""
    echo "══════════════════════════════════════════════════════════════"
    echo "  ❌ NOT LOGGED IN"
    echo ""
    echo "  Step 1: Run with your account number:"
    echo "     mullvad account login YOUR_ACCOUNT_NUMBER"
    echo ""
    echo "  Step 2: Re-run this script."
    echo "══════════════════════════════════════════════════════════════"
    exit 1
fi

# Show account expiry if available (cosmetic, doesn't fail script if missing)
ACCT_EXPIRY=""
ACCT_VERBOSE="$(mullvad account get 2>/dev/null || true)"
if [ -n "$ACCT_VERBOSE" ]; then
    ACCT_EXPIRY="$(echo "$ACCT_VERBOSE" \
        | grep -iE 'expir' \
        | head -1 \
        | sed -E 's/^[^:]+:[[:space:]]*//')"
fi
if [ -n "$ACCT_EXPIRY" ]; then
    echo "✅ Mullvad account (expires: $ACCT_EXPIRY)"
else
    echo "✅ Mullvad account"
fi

# --- LOGGING ---
touch "$LOG_FILE" || { echo "❌ FAIL: Cannot write $LOG_FILE"; exit 1; }
exec > >(tee -a "$LOG_FILE") 2>&1
echo ""
echo "[$(date)] 🚀 Starting Hardened Gateway v${SCRIPT_VERSION}"
echo "[$(date)] ⚙️  Config: LAN_IF=$LAN_IF WG_MTU=$WG_MTU MSS_CLAMP=$MSS_CLAMP CAKE_BW=$CAKE_BW LOCKDOWN=$ENABLE_LOCKDOWN"

# --- SSH SAFETY ---
restore_ssh() {
    echo "[$(date)] 🚨 restore_ssh() — emergency firewall reset"
    iptables  -P INPUT   ACCEPT 2>/dev/null || true
    iptables  -P FORWARD ACCEPT 2>/dev/null || true
    iptables  -P OUTPUT  ACCEPT 2>/dev/null || true
    iptables  -F            2>/dev/null || true
    iptables  -t nat    -F  2>/dev/null || true
    iptables  -t mangle -F  2>/dev/null || true
    ip6tables -P INPUT   ACCEPT 2>/dev/null || true
    ip6tables -P FORWARD ACCEPT 2>/dev/null || true
    ip6tables -P OUTPUT  ACCEPT 2>/dev/null || true
    ip6tables -F            2>/dev/null || true
    ip6tables -t nat    -F  2>/dev/null || true
    ip6tables -t mangle -F  2>/dev/null || true
}

fail() {
    echo "[$(date)] ❌ FAIL: $*"
    restore_ssh
    exit 1
}

trap restore_ssh ERR
trap 'echo "[$(date)] 🛑 Caught signal — cleaning up"; restore_ssh; exit 130' INT TERM

# --- HELPERS ---
clean_ban_list() {
    [ -f "$BAN_FILE" ] || return 0
    local NOW
    NOW=$(date +%s)
    awk -v expiry="$((NOW - 28800))" '$1 > expiry' "$BAN_FILE" > "${BAN_FILE}.tmp" \
        && mv "${BAN_FILE}.tmp" "$BAN_FILE"
}

get_valid_country() {
    clean_ban_list
    local AVAILABLE=()
    for c in "${ALLOWED_COUNTRIES[@]}"; do
        grep -q " $c$" "$BAN_FILE" 2>/dev/null || AVAILABLE+=("$c")
    done
    if [ "${#AVAILABLE[@]}" -eq 0 ]; then
        : > "$BAN_FILE"
        AVAILABLE=("${ALLOWED_COUNTRIES[@]}")
    fi
    local LAST=""
    [ -f "$LAST_USED_FILE" ] && LAST="$(cat "$LAST_USED_FILE")"
    local CANDS=()
    for c in "${AVAILABLE[@]}"; do
        [ "$c" != "$LAST" ] && CANDS+=("$c")
    done
    [ "${#CANDS[@]}" -eq 0 ] && CANDS=("${AVAILABLE[@]}")
    local SEL="${CANDS[$((RANDOM % ${#CANDS[@]}))]}"
    echo "$SEL" > "$LAST_USED_FILE"
    echo "$SEL"
}

set_features() {
    mullvad anti-censorship set mode quic 2>/dev/null \
        || mullvad obfuscation set mode quic 2>/dev/null \
        || echo "  ⚠️  WARN: QUIC mode not set"

    mullvad tunnel wireguard quantum-resistant on 2>/dev/null \
        || mullvad tunnel set quantum-resistant on 2>/dev/null \
        || true

    if [ "${WANT_DAITA:-1}" = "1" ]; then
        mullvad tunnel wireguard daita on 2>/dev/null \
            || mullvad tunnel set daita on 2>/dev/null \
            || true
    else
        mullvad tunnel wireguard daita off 2>/dev/null \
            || mullvad tunnel set daita off 2>/dev/null \
            || true
    fi

    mullvad lan set allow 2>/dev/null || true
}

get_status_state() {
    local J
    J="$(mullvad status --json 2>/dev/null || echo '{}')"
    if echo "$J" | grep -q '"state"'; then
        echo "$J" \
            | grep -oE '"state"[[:space:]]*:[[:space:]]*"[^"]+"' \
            | head -1 \
            | sed -E 's/.*"state"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' \
            | tr '[:upper:]' '[:lower:]'
    else
        local FIRST
        FIRST="$(mullvad status 2>/dev/null | head -1 | tr '[:upper:]' '[:lower:]')"
        # Order matters — disconnected/connecting both contain "connected" as substring
        case "$FIRST" in
            *disconnected*)    echo "disconnected" ;;
            *connecting*)      echo "connecting"   ;;
            *connected*)       echo "connected"    ;;
            *blocked*|*error*) echo "error"        ;;
            *)                 echo "unknown"      ;;
        esac
    fi
}

# Parse `mullvad status -v` for relay name and location string.
# Format (from Mullvad docs): "Connected to se-got-wg-004 in Gothenburg, Sweden"
# Multihop:                    "Connected to se-got-wg-004 via dk-cph-wg-001 in Gothenburg, Sweden"
get_relay_info() {
    local STATUS_V="$1"
    local FIRST
    FIRST="$(echo "$STATUS_V" | head -1)"

    local RELAY="" ENTRY="" LOCATION=""
    # Extract "to <relay>" — the exit relay
    RELAY="$(echo "$FIRST" | sed -nE 's/.*[Cc]onnected to[[:space:]]+([a-z0-9-]+).*/\1/p')"
    # Extract "via <entry>" — multihop entry, if present
    ENTRY="$(echo "$FIRST" | sed -nE 's/.*via[[:space:]]+([a-z0-9-]+).*/\1/p')"
    # Extract "in <location>"
    LOCATION="$(echo "$FIRST" | sed -nE 's/.*in[[:space:]]+(.*[A-Za-z]).*/\1/p' | sed 's/\.$//')"

    echo "$RELAY|$ENTRY|$LOCATION"
}

# --- HOST KILL-SWITCH (off during connect; on after verified) ---
mullvad lockdown-mode set off 2>/dev/null || true

# --- KILL PRIOR WATCHDOG ---
if [ -f "$WATCHDOG_PIDFILE" ]; then
    OLD_PID="$(cat "$WATCHDOG_PIDFILE" 2>/dev/null || echo)"
    if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        kill "$OLD_PID" 2>/dev/null || true
        sleep 1
    fi
    rm -f "$WATCHDOG_PIDFILE"
fi
pkill -f "$WATCHDOG_TAG" 2>/dev/null || true

# --- FIREWALL LOCKDOWN ---
iptables -P FORWARD DROP || fail "iptables policy FORWARD DROP failed"
iptables -P INPUT   DROP || fail "iptables policy INPUT DROP failed"
iptables -P OUTPUT  ACCEPT
iptables -F             || fail "iptables flush failed"
iptables -t nat    -F   || fail "nat flush failed"
iptables -t mangle -F   || fail "mangle flush failed"

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i "$LAN_IF" -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -i "$LAN_IF" -p icmp -j ACCEPT

ip6tables -P INPUT   DROP   2>/dev/null || true
ip6tables -P FORWARD DROP   2>/dev/null || true
ip6tables -P OUTPUT  DROP   2>/dev/null || true
ip6tables -F                2>/dev/null || true
ip6tables -A INPUT  -i lo -j ACCEPT 2>/dev/null || true
ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true

DRIVER="$(ethtool -i "$LAN_IF" 2>/dev/null | awk -F': ' '/^driver/ {print $2}')"
if [ -n "$DRIVER" ] && [ "$DRIVER" != "virtio_net" ]; then
    ethtool --set-eee "$LAN_IF" eee off 2>/dev/null || true
fi

sysctl -w net.ipv4.ip_forward=1 > /dev/null || fail "ip_forward sysctl failed"
sysctl -w net.ipv6.conf.all.disable_ipv6=1 2>/dev/null || true
sysctl -w net.ipv6.conf.default.disable_ipv6=1 2>/dev/null || true
if [ -n "$LAN_IF" ]; then
    sysctl -w "net.ipv6.conf.${LAN_IF}.disable_ipv6=1" 2>/dev/null || true
fi

echo "[$(date)] 🛡️  Firewall locked (FORWARD=DROP, IPv6=DROP)"

# --- CONNECT ---
connect_mullvad() {
    local CC="$1"
    echo "[$(date)] 🔗 Connecting to ${CC^^}..."

    mullvad disconnect 2>/dev/null || true
    sleep 2

    if ! systemctl is-active --quiet mullvad-daemon; then
        systemctl start mullvad-daemon
        sleep 5
    fi

    mullvad relay set location "$CC" || { echo "  ⚠️  WARN: relay set failed"; return 1; }
    set_features

    local CONNECT_OUT
    CONNECT_OUT="$(timeout 60 mullvad connect --wait 2>&1)"
    local CONNECT_RC=$?

    if echo "$CONNECT_OUT" | grep -qi "not logged in"; then
        echo ""
        echo "══════════════════════════════════════════════════════════════"
        echo "  ❌ NOT LOGGED IN — daemon lost session"
        echo "  Run: mullvad account login YOUR_ACCOUNT_NUMBER"
        echo "  Then re-run this script."
        echo "══════════════════════════════════════════════════════════════"
        restore_ssh
        exit 1
    fi

    local STATE
    STATE="$(get_status_state)"
    if [ "$STATE" != "connected" ]; then
        echo "[$(date)] ⚠️  connect --wait returned rc=$CONNECT_RC, state=$STATE"
        return 1
    fi

    local WG_IF=""
    local WAIT=0
    while [ $WAIT -lt 15 ]; do
        WG_IF="$(ip -br link show 2>/dev/null | grep -oE 'wg[0-9]?-mullvad' | head -1)"
        [ -n "$WG_IF" ] && break
        sleep 1
        WAIT=$((WAIT + 1))
    done
    if [ -z "$WG_IF" ]; then
        echo "[$(date)] ❌ No wg-mullvad interface appeared"
        return 1
    fi
    echo "[$(date)] ✅ Interface created: $WG_IF"
    echo "$WG_IF" > /var/tmp/mullvad_current_if

    ip link set dev "$WG_IF" mtu "$WG_MTU" || echo "  ⚠️  WARN: MTU set failed"
    iptables -A FORWARD -i "$LAN_IF" -o "$WG_IF" -j ACCEPT
    iptables -t nat -A POSTROUTING -o "$WG_IF" -j MASQUERADE

    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
        -j TCPMSS --set-mss "$MSS_CLAMP"
    iptables -t mangle -A OUTPUT  -p tcp --tcp-flags SYN,RST SYN \
        -o "$WG_IF" -j TCPMSS --set-mss "$MSS_CLAMP"

    iptables -A FORWARD -i "$LAN_IF" -p udp --dport 53 ! -o "$WG_IF" -j DROP
    iptables -A FORWARD -i "$LAN_IF" -p tcp --dport 53 ! -o "$WG_IF" -j DROP

    modprobe sch_cake 2>/dev/null || true
    tc qdisc del dev "$LAN_IF" root 2>/dev/null || true
    tc qdisc add dev "$LAN_IF" root cake bandwidth "$CAKE_BW" nat wash ack-filter 2>/dev/null \
        || echo "  ⚠️  WARN: CAKE qdisc setup failed"

    echo "[$(date)] 🛡️  Tunnel rules applied (NAT, MSS clamp, DNS lock, CAKE)"
    return 0
}

TARGET="$(get_valid_country)"
echo "[$(date)] 🌍 Target: ${TARGET^^}"

WANT_DAITA=1
if ! connect_mullvad "$TARGET"; then
    echo "[$(date)] 🔄 Initial connect failed — retrying without DAITA..."
    WANT_DAITA=0
    if ! connect_mullvad "$TARGET"; then
        echo "[$(date)] 🔄 Trying alternate country..."
        ALT_TARGET="$(get_valid_country)"
        if [ "$ALT_TARGET" = "$TARGET" ]; then
            ALT_TARGET="${ALLOWED_COUNTRIES[0]}"
        fi
        if ! connect_mullvad "$ALT_TARGET"; then
            fail "Could not establish any tunnel"
        fi
        TARGET="$ALT_TARGET"
    fi
fi

# --- VERIFY ---
echo "[$(date)] 🔍 Verifying connection..."
WG_IF="$(cat /var/tmp/mullvad_current_if 2>/dev/null || echo '?')"
STATE="$(get_status_state)"

IP="$(curl -s --max-time 8 https://am.i.mullvad.net/ip 2>/dev/null || echo 'Unknown')"
FULL_STATUS="$(mullvad status -v 2>/dev/null || mullvad status 2>/dev/null || echo)"

# Parse relay info from verbose status
RELAY_INFO="$(get_relay_info "$FULL_STATUS")"
RELAY_NAME="${RELAY_INFO%%|*}"
ENTRY_NAME="$(echo "$RELAY_INFO" | cut -d'|' -f2)"
LOCATION="$(echo "$RELAY_INFO" | cut -d'|' -f3)"

# Tunnel IPv4 (best effort)
TUN_IP4="$(echo "$FULL_STATUS" | grep -iE '^[[:space:]]*IPv4:' | head -1 | awk '{print $2}')"

# Feature detection
OBF_RAW="none"
echo "$FULL_STATUS" | grep -qi "quic"        && OBF_RAW="quic"
echo "$FULL_STATUS" | grep -qi "shadowsocks" && OBF_RAW="shadowsocks"
echo "$FULL_STATUS" | grep -qi "udp2tcp"     && OBF_RAW="udp2tcp"
echo "$FULL_STATUS" | grep -qi "lwo"         && OBF_RAW="lwo"

DAITA_ST="off"
echo "$FULL_STATUS" | grep -qi "daita" && DAITA_ST="on"
QUANTUM_ST="off"
echo "$FULL_STATUS" | grep -qi "quantum" && QUANTUM_ST="on"
MULTIHOP="off"
[ -n "$ENTRY_NAME" ] && MULTIHOP="on"
echo "$FULL_STATUS" | grep -qi "multihop" && MULTIHOP="on"

# Engage host kill-switch only after verified connection
LOCKDOWN_ST="off"
if [ "$ENABLE_LOCKDOWN" = "1" ] && [ "$STATE" = "connected" ]; then
    if mullvad lockdown-mode set on 2>/dev/null; then
        LOCKDOWN_ST="on"
    fi
fi

# Annotated values for the report
OBF_DESC="$(obf_descriptor "$OBF_RAW")"
MSS_DESC="$(mss_descriptor "$MSS_CLAMP")"
MTU_DESC="$(mtu_descriptor "$WG_MTU")"

# Connection-established banner (matches README style)
echo ""
echo "[$(date)] ✅ Connection Established!"

# Comprehensive status report
echo ""
echo "══════════════════════════ STATUS REPORT ══════════════════════════"
printf "  %-14s %s\n" "STATE:"       "$STATE"
[ -n "$RELAY_NAME" ] && printf "  %-14s %s\n" "RELAY:"       "$RELAY_NAME"
[ -n "$ENTRY_NAME" ] && printf "  %-14s %s\n" "ENTRY (hop):" "$ENTRY_NAME"
[ -n "$LOCATION" ]   && printf "  %-14s %s\n" "LOCATION:"    "$LOCATION"
printf "  %-14s %s\n" "PUBLIC IP:"   "$IP"
[ -n "$TUN_IP4" ]    && printf "  %-14s %s\n" "TUNNEL IPv4:" "$TUN_IP4"
printf "  %-14s %s\n" "INTERFACE:"   "$WG_IF"
echo  "  ─────────────────────────────────────────────────────────────"
printf "  %-14s %s (%s)\n" "OBFUSCATION:" "$OBF_RAW"   "$OBF_DESC"
printf "  %-14s %s\n"     "QUANTUM:"     "$QUANTUM_ST"
printf "  %-14s %s\n"     "DAITA:"       "$DAITA_ST"
printf "  %-14s %s\n"     "MULTIHOP:"    "$MULTIHOP"
echo  "  ─────────────────────────────────────────────────────────────"
printf "  %-14s %s (%s)\n" "WG MTU:"    "$WG_MTU"    "$MTU_DESC"
printf "  %-14s %s (%s)\n" "MSS CLAMP:" "$MSS_CLAMP" "$MSS_DESC"
printf "  %-14s CAKE (%s)\n" "QUEUE:"   "$CAKE_BW"
echo  "  ─────────────────────────────────────────────────────────────"
printf "  %-14s %s  (Mullvad host kill-switch)\n" "LOCKDOWN:"  "$LOCKDOWN_ST"
printf "  %-14s DROP (tunnel-only)\n"             "FWD POLICY:"
echo "═══════════════════════════════════════════════════════════════════"

# --- WATCHDOG ---
(
exec -a "$WATCHDOG_TAG" bash <<EOF_WATCHDOG
set -uo pipefail
LAN_IF='$LAN_IF'
WG_MTU=$WG_MTU
MSS_CLAMP=$MSS_CLAMP
CAKE_BW='$CAKE_BW'
ALLOWED_COUNTRIES=($(printf "'%s' " "${ALLOWED_COUNTRIES[@]}"))
BAN_FILE='$BAN_FILE'
LAST_USED_FILE='$LAST_USED_FILE'
LOG_FILE='$LOG_FILE'

FAIL_COUNT=0
THRESHOLD=3
BACKOFF_LEVEL=0
BACKOFF=(10 30 60 120 300)
CURRENT_IF="\$(cat /var/tmp/mullvad_current_if 2>/dev/null || echo)"
CURRENT_COUNTRY="\$(cat "\$LAST_USED_FILE" 2>/dev/null || echo)"

log() { echo "[\$(date)] \$*" >> "\$LOG_FILE"; }
log "👁️  Watchdog active (IF=\$CURRENT_IF country=\$CURRENT_COUNTRY)"

cleanup_iface() {
    local IF="\$1"
    [ -z "\$IF" ] && return
    iptables    -D FORWARD -i "\$LAN_IF" -o "\$IF" -j ACCEPT 2>/dev/null || true
    iptables -t nat -D POSTROUTING -o "\$IF" -j MASQUERADE   2>/dev/null || true
    conntrack -F 2>/dev/null || true
}

reapply_rules() {
    local NEW_IF="\$1"
    ip link set dev "\$NEW_IF" mtu "\$WG_MTU" 2>/dev/null || true
    iptables    -A FORWARD -i "\$LAN_IF" -o "\$NEW_IF" -j ACCEPT
    iptables -t nat -A POSTROUTING -o "\$NEW_IF" -j MASQUERADE
    iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN \
        -j TCPMSS --set-mss "\$MSS_CLAMP" 2>/dev/null \
        || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
            -j TCPMSS --set-mss "\$MSS_CLAMP"
    iptables -t mangle -C OUTPUT -p tcp --tcp-flags SYN,RST SYN \
        -o "\$NEW_IF" -j TCPMSS --set-mss "\$MSS_CLAMP" 2>/dev/null \
        || iptables -t mangle -A OUTPUT  -p tcp --tcp-flags SYN,RST SYN \
            -o "\$NEW_IF" -j TCPMSS --set-mss "\$MSS_CLAMP"
    iptables -C FORWARD -i "\$LAN_IF" -p udp --dport 53 ! -o "\$NEW_IF" -j DROP 2>/dev/null \
        || iptables -A FORWARD -i "\$LAN_IF" -p udp --dport 53 ! -o "\$NEW_IF" -j DROP
    iptables -C FORWARD -i "\$LAN_IF" -p tcp --dport 53 ! -o "\$NEW_IF" -j DROP 2>/dev/null \
        || iptables -A FORWARD -i "\$LAN_IF" -p tcp --dport 53 ! -o "\$NEW_IF" -j DROP
    modprobe sch_cake 2>/dev/null || true
    tc qdisc del dev "\$LAN_IF" root 2>/dev/null || true
    tc qdisc add dev "\$LAN_IF" root cake bandwidth "\$CAKE_BW" nat wash ack-filter 2>/dev/null || true
}

while true; do
    sleep 10

    HEALTHY=true
    STATE_J="\$(mullvad status --json 2>/dev/null || echo '{}')"
    if ! echo "\$STATE_J" | grep -qE '"state"[[:space:]]*:[[:space:]]*"connected"'; then
        if ! mullvad status 2>/dev/null | head -1 | grep -qi "connected"; then
            HEALTHY=false
        fi
    fi
    \$HEALTHY && ! ping -c 1 -W 3 1.1.1.1 >/dev/null 2>&1 && HEALTHY=false

    if \$HEALTHY; then
        if [ \$FAIL_COUNT -ne 0 ] || [ \$BACKOFF_LEVEL -ne 0 ]; then
            log "💚 Health restored"
        fi
        FAIL_COUNT=0
        BACKOFF_LEVEL=0
        continue
    fi

    FAIL_COUNT=\$((FAIL_COUNT + 1))
    log "⚠️  Connection drop detected (\$FAIL_COUNT/\$THRESHOLD)"
    [ \$FAIL_COUNT -lt \$THRESHOLD ] && continue

    [ -n "\$CURRENT_COUNTRY" ] && echo "\$(date +%s) \$CURRENT_COUNTRY" >> "\$BAN_FILE"
    cleanup_iface "\$CURRENT_IF"

    NOW=\$(date +%s)
    EXPIRY=\$((NOW - 28800))
    [ -f "\$BAN_FILE" ] && {
        awk -v expiry="\$EXPIRY" '\$1 > expiry' "\$BAN_FILE" > "\${BAN_FILE}.tmp" \
            && mv "\${BAN_FILE}.tmp" "\$BAN_FILE"
    }
    AVAILABLE=()
    for c in "\${ALLOWED_COUNTRIES[@]}"; do
        grep -q " \$c\$" "\$BAN_FILE" 2>/dev/null || AVAILABLE+=("\$c")
    done
    if [ "\${#AVAILABLE[@]}" -eq 0 ]; then
        : > "\$BAN_FILE"
        AVAILABLE=("\${ALLOWED_COUNTRIES[@]}")
    fi
    NEW_COUNTRY="\${AVAILABLE[\$((RANDOM % \${#AVAILABLE[@]}))]}"
    log "🔄 Migrating to \${NEW_COUNTRY^^}"

    RECOVERED=false
    for daita_attempt in on off; do
        mullvad disconnect 2>/dev/null || true
        sleep 2
        mullvad relay set location "\$NEW_COUNTRY" 2>/dev/null || true
        mullvad anti-censorship set mode quic 2>/dev/null \
            || mullvad obfuscation set mode quic 2>/dev/null || true
        mullvad tunnel wireguard quantum-resistant on 2>/dev/null \
            || mullvad tunnel set quantum-resistant on 2>/dev/null || true
        mullvad tunnel wireguard daita "\$daita_attempt" 2>/dev/null \
            || mullvad tunnel set daita "\$daita_attempt" 2>/dev/null || true

        timeout 60 mullvad connect --wait >/dev/null 2>&1
        sleep 2

        STATE_J="\$(mullvad status --json 2>/dev/null || echo '{}')"
        if echo "\$STATE_J" | grep -qE '"state"[[:space:]]*:[[:space:]]*"connected"' \
            || mullvad status 2>/dev/null | head -1 | grep -qi "connected"; then

            NEW_IF="\$(ip -br link show 2>/dev/null | grep -oE 'wg[0-9]?-mullvad' | head -1)"
            if [ -n "\$NEW_IF" ]; then
                reapply_rules "\$NEW_IF"
                echo "\$NEW_IF" > /var/tmp/mullvad_current_if
                echo "\$NEW_COUNTRY" > "\$LAST_USED_FILE"
                CURRENT_IF="\$NEW_IF"
                CURRENT_COUNTRY="\$NEW_COUNTRY"
                FAIL_COUNT=0
                BACKOFF_LEVEL=0
                log "✅ Recovered in \${NEW_COUNTRY^^} via \$NEW_IF (daita=\$daita_attempt)"
                RECOVERED=true
                break
            fi
        fi
    done

    if ! \$RECOVERED; then
        BACKOFF_TIME=\${BACKOFF[\$BACKOFF_LEVEL]}
        log "⏳ Recovery failed; backing off \${BACKOFF_TIME}s"
        sleep "\$BACKOFF_TIME"
        if [ \$BACKOFF_LEVEL -lt \$((\${#BACKOFF[@]} - 1)) ]; then
            BACKOFF_LEVEL=\$((BACKOFF_LEVEL + 1))
        fi
        FAIL_COUNT=0
    fi
done
EOF_WATCHDOG
) & disown
WATCHDOG_PID=$!
echo "$WATCHDOG_PID" > "$WATCHDOG_PIDFILE"

trap - ERR
trap - INT TERM
echo ""
echo "[$(date)] 👁️  Watchdog launched (PID: $WATCHDOG_PID)"
echo "[$(date)] 🚀 Gateway ready"
echo ""
echo "  📜 Logs:    tail -f $LOG_FILE"
echo "  🔧 Service: cp mullvad-gateway.service /etc/systemd/system/"
echo "              systemctl daemon-reload && systemctl enable mullvad-gateway"
echo ""
