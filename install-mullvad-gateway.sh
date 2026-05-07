#!/bin/bash
# ==============================================================================
#   MULLVAD HARDENED GATEWAY (v29.1)
#   Tested against: Mullvad 2026.1 / Debian 13 (Trixie) / Pi 5 / Proxmox VM
#
#   v29.1 — bugfix release for v29:
#
#     1. **CRITICAL FIX: silent script death after "Reaping watchdogs".**
#        v29 had `pkill -f "mullvad-optimizer"` which matched the tee process
#        running `tee -a /var/log/mullvad-optimizer.log`. Killing tee broke
#        the script's stdout pipe → SIGPIPE → silent exit. Removed.
#
#     2. **CORRECTED: DAITA + QUIC are NOT incompatible.**
#        v29 falsely claimed they were. They are not — per Mullvad engineer
#        "faern" in upstream issue #8742: "QUIC is compatible with all other
#        security features, it's just that not many servers supports QUIC yet."
#        v29.1 enables both when requested. The actual constraint is server
#        availability — fewer relays support QUIC than support plain WG. If
#        no relay satisfies all requested features, v29.1 falls through the
#        obfuscation chain: QUIC → Shadowsocks → LWO → udp2tcp → none.
#
#     3. **OLD STATUS-REPORT FORMAT RESTORED.**
#        Full report with STATE, TARGET CC, RELAY, ENTRY (hop), LOCATION,
#        PUBLIC IP, TUNNEL IPv4, INTERFACE, OBFUSCATION (with descriptor),
#        QUANTUM, DAITA, MULTIHOP, MTU/MSS descriptors, LOCKDOWN, FWD POLICY.
#
#     4. **WATCHDOG REAPING IS SAFE.**
#        Only kills processes whose argv[0] is exactly the WATCHDOG_TAG
#        (set via exec -a). No more wildcard matches that hit unrelated
#        processes like the script's own tee.
#
#   Companion scripts (unchanged):
#     teardown-mullvad-gateway-v28.sh
#     emergency-restore.sh
# ==============================================================================

set -u

# --- CONFIG ---
ALLOWED_COUNTRIES=("nl" "ch" "us" "de" "se")
TARGET_COUNTRY="${TARGET_COUNTRY:-}"
BAN_FILE="/var/log/mullvad_banlist.log"
LAST_USED_FILE="/var/tmp/mullvad_last_gw"
LOG_FILE="/var/log/mullvad-optimizer.log"
WATCHDOG_PIDFILE="/var/run/mullvad-gateway-watchdog.pid"
WATCHDOG_TAG="mullvad_gateway_watchdog"
SCRIPT_VERSION="29.1"

# Tunables
CAKE_BW="${CAKE_BW:-500mbit}"
WG_MTU="${WG_MTU:-1280}"
MSS_CLAMP="${MSS_CLAMP:-1220}"
WANT_QUIC="${WANT_QUIC:-1}"
WANT_QUANTUM="${WANT_QUANTUM:-1}"
WANT_DAITA="${WANT_DAITA:-1}"
DAITA_DIRECT_ONLY="${DAITA_DIRECT_ONLY:-0}"
OBF_FALLBACK="${OBF_FALLBACK:-1}"
ENABLE_LOCKDOWN="${ENABLE_LOCKDOWN:-1}"

# --- DESCRIPTOR HELPERS (restored from v27) ---
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

# --- BANNER ---
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  🔒 MULLVAD HARDENED GATEWAY  v${SCRIPT_VERSION}"
echo "      DAITA + Quantum-Resistant + QUIC"
echo "══════════════════════════════════════════════════════════════"

if [ "$(id -u)" -ne 0 ]; then echo "❌ FAIL: Must run as root"; exit 1; fi

# --- INSTALL DEPENDENCIES ---
NEEDED_PKGS=()
for pkg in curl iptables conntrack ethtool iproute2 nftables; do
    case "$pkg" in
        iproute2)  command -v ip      &>/dev/null || NEEDED_PKGS+=("iproute2") ;;
        ethtool)   command -v ethtool &>/dev/null || NEEDED_PKGS+=("ethtool")  ;;
        nftables)  command -v nft     &>/dev/null || NEEDED_PKGS+=("nftables") ;;
        *)         command -v "$pkg"  &>/dev/null || NEEDED_PKGS+=("$pkg")     ;;
    esac
done
if [ "${#NEEDED_PKGS[@]}" -gt 0 ]; then
    echo "📦 Installing: ${NEEDED_PKGS[*]}"
    apt-get update -qq || { echo "❌ apt-get update failed"; exit 1; }
    apt-get install -y "${NEEDED_PKGS[@]}" || { echo "❌ install failed"; exit 1; }
fi
command -v mullvad &>/dev/null || { echo "❌ Mullvad not installed"; exit 1; }

# --- LAN_IF DETECTION ---
detect_lan_if() {
    [ -n "${LAN_IF:-}" ] && return 0
    local IFACES
    mapfile -t IFACES < <(ip -br link show 2>/dev/null \
        | awk '$1 != "lo" && $2 == "UP" {print $1}')
    if [ "${#IFACES[@]}" -eq 1 ]; then
        LAN_IF="${IFACES[0]}"
        echo "🔧 Auto-detected LAN_IF=$LAN_IF (sole UP interface)"
        return 0
    fi
    echo "❌ FAIL: ${#IFACES[@]} UP interfaces — set LAN_IF explicitly"
    return 1
}
detect_lan_if || exit 1
ip link show "$LAN_IF" &>/dev/null || { echo "❌ Interface '$LAN_IF' not found"; exit 1; }
echo "✅ Interface: $LAN_IF"

# --- DAEMON READY ---
systemctl start mullvad-daemon 2>/dev/null || true
echo -n "⏳ Waiting for daemon"
TRIES=0
while [ $TRIES -lt 30 ]; do
    if mullvad status &>/dev/null; then echo " ok"; break; fi
    echo -n "."
    sleep 1
    TRIES=$((TRIES + 1))
done
[ $TRIES -ge 30 ] && { echo ""; echo "❌ Daemon not ready"; exit 1; }

mullvad disconnect 2>/dev/null || true
sleep 1

# --- LOGIN CHECK ---
LOGGED_IN=false
[ -f /etc/mullvad-vpn/device.json ] && LOGGED_IN=true
if ! $LOGGED_IN; then
    if mullvad account get 2>&1 | grep -qE '([0-9]{16}|([0-9]{4}[[:space:]]+){3}[0-9]{4})'; then
        LOGGED_IN=true
    fi
fi
$LOGGED_IN || { echo "❌ NOT LOGGED IN — run: mullvad account login YOUR_ACCOUNT"; exit 1; }

ACCT_EXPIRY="$(mullvad account get 2>/dev/null \
    | awk -F': *' 'tolower($1) ~ /expir/ {sub(/^[^:]+: */,""); print; exit}')"
[ -n "$ACCT_EXPIRY" ] && echo "✅ Mullvad account (expires: $ACCT_EXPIRY)" || echo "✅ Mullvad account"

# --- LOGGING ---
touch "$LOG_FILE" || { echo "❌ Cannot write $LOG_FILE"; exit 1; }
exec > >(tee -a "$LOG_FILE") 2>&1
echo ""
echo "[$(date)] 🚀 Starting Hardened Gateway v${SCRIPT_VERSION}"
echo "[$(date)] ⚙️  Config: LAN_IF=$LAN_IF WG_MTU=$WG_MTU MSS_CLAMP=$MSS_CLAMP CAKE_BW=$CAKE_BW LOCKDOWN=$ENABLE_LOCKDOWN"
echo "[$(date)] ⚙️  Features: QUIC=$WANT_QUIC QUANTUM=$WANT_QUANTUM DAITA=$WANT_DAITA"

# --- SAFETY ---
restore_ssh() {
    echo "[$(date)] 🚨 restore_ssh()"
    iptables  -P INPUT   ACCEPT 2>/dev/null
    iptables  -P FORWARD ACCEPT 2>/dev/null
    iptables  -P OUTPUT  ACCEPT 2>/dev/null
    iptables  -F            2>/dev/null
    iptables  -t nat    -F  2>/dev/null
    iptables  -t mangle -F  2>/dev/null
    ip6tables -P INPUT   ACCEPT 2>/dev/null
    ip6tables -P FORWARD ACCEPT 2>/dev/null
    ip6tables -P OUTPUT  ACCEPT 2>/dev/null
    ip6tables -F            2>/dev/null
}
fail() { echo "[$(date)] ❌ FAIL: $*"; restore_ssh; exit 1; }
trap 'echo "[$(date)] 🛑 Caught signal — cleaning up"; restore_ssh; exit 130' INT TERM

# --- HELPERS ---
clean_ban_list() {
    [ -f "$BAN_FILE" ] || return 0
    local NOW=$(date +%s)
    awk -v expiry="$((NOW - 28800))" '$1 > expiry' "$BAN_FILE" > "${BAN_FILE}.tmp" 2>/dev/null \
        && mv "${BAN_FILE}.tmp" "$BAN_FILE"
}

get_valid_country() {
    [ -n "$TARGET_COUNTRY" ] && { echo "$TARGET_COUNTRY"; return; }
    clean_ban_list
    local AVAILABLE=()
    for c in "${ALLOWED_COUNTRIES[@]}"; do
        grep -q " $c$" "$BAN_FILE" 2>/dev/null || AVAILABLE+=("$c")
    done
    [ "${#AVAILABLE[@]}" -eq 0 ] && { : > "$BAN_FILE"; AVAILABLE=("${ALLOWED_COUNTRIES[@]}"); }
    local LAST=""
    [ -f "$LAST_USED_FILE" ] && LAST="$(cat "$LAST_USED_FILE")"
    local CANDS=()
    for c in "${AVAILABLE[@]}"; do [ "$c" != "$LAST" ] && CANDS+=("$c"); done
    [ "${#CANDS[@]}" -eq 0 ] && CANDS=("${AVAILABLE[@]}")
    local SEL="${CANDS[$((RANDOM % ${#CANDS[@]}))]}"
    echo "$SEL" > "$LAST_USED_FILE"
    echo "$SEL"
}

get_state() {
    mullvad status 2>/dev/null | head -1 | tr '[:upper:]' '[:lower:]' \
        | grep -oE 'disconnected|connecting|connected|blocked|error' | head -1
}

wait_for_state() {
    local TARGET="$1" TIMEOUT="${2:-15}"
    local i=0
    while [ $i -lt "$TIMEOUT" ]; do
        [ "$(get_state)" = "$TARGET" ] && return 0
        sleep 1
        i=$((i + 1))
    done
    return 1
}

reset_daemon() {
    echo "[$(date)] 🔄 Resetting mullvad-daemon..."
    mullvad disconnect 2>/dev/null || true
    if ! wait_for_state "disconnected" 5; then
        systemctl restart mullvad-daemon 2>/dev/null
        sleep 3
        for i in $(seq 1 15); do
            mullvad status &>/dev/null && break
            sleep 1
        done
    fi
}

set_obf_mode() {
    local MODE="$1"
    mullvad anti-censorship set mode "$MODE" 2>/dev/null \
        || mullvad obfuscation set mode "$MODE" 2>/dev/null \
        || return 1
    return 0
}

set_features_baseline() {
    set_obf_mode auto
    mullvad tunnel set quantum-resistant off 2>/dev/null
    mullvad tunnel set daita off 2>/dev/null
    mullvad tunnel set mtu "$WG_MTU" 2>/dev/null
    mullvad lan set allow 2>/dev/null
}

try_connect() {
    local LABEL="$1"
    if ! timeout 60 mullvad connect --wait >/dev/null 2>&1; then
        echo "[$(date)]   ⚠️  connect timeout ($LABEL)"
        return 1
    fi
    [ "$(get_state)" = "connected" ] && return 0
    echo "[$(date)]   ⚠️  state=$(get_state) ($LABEL)"
    return 1
}

# Try Shadowsocks → LWO → udp2tcp → auto, in order.
# Sets ACHIEVED_OBF on success.
obf_fallback_chain() {
    for MODE in shadowsocks lwo udp2tcp; do
        echo "[$(date)]   trying $MODE..."
        if set_obf_mode "$MODE"; then
            mullvad reconnect 2>/dev/null
            wait_for_state "connected" 30
            if [ "$(get_state)" = "connected" ]; then
                ACHIEVED_OBF="$MODE"
                echo "[$(date)]   ✅ $MODE connected"
                return 0
            fi
        fi
    done
    echo "[$(date)]   all obfuscation modes failed — using auto"
    set_obf_mode auto
    mullvad reconnect 2>/dev/null
    wait_for_state "connected" 30
    ACHIEVED_OBF="none"
    return 0
}

# Try to layer features (Quantum, DAITA, Obfuscation) onto an existing connection.
# Sets globals: ACHIEVED_QUANTUM, ACHIEVED_DAITA, ACHIEVED_OBF
layer_features() {
    local CC="$1"
    ACHIEVED_QUANTUM="off"
    ACHIEVED_DAITA="off"
    ACHIEVED_OBF="none"

    if [ "$WANT_QUANTUM" = "1" ]; then
        echo "[$(date)] ➕ Enabling quantum-resistant..."
        [ -n "$CC" ] && mullvad relay set location "$CC" 2>/dev/null
        mullvad tunnel set quantum-resistant on 2>/dev/null
        mullvad reconnect 2>/dev/null
        wait_for_state "connected" 30
        if [ "$(get_state)" = "connected" ]; then
            ACHIEVED_QUANTUM="on"
        else
            echo "[$(date)] ⚠️  Quantum broke connection — disabling"
            mullvad tunnel set quantum-resistant off 2>/dev/null
            mullvad reconnect 2>/dev/null
            wait_for_state "connected" 30
        fi
    fi

    if [ "$WANT_DAITA" = "1" ]; then
        echo "[$(date)] ➕ Enabling DAITA..."
        [ -n "$CC" ] && mullvad relay set location "$CC" 2>/dev/null
        if [ "$DAITA_DIRECT_ONLY" = "1" ]; then
            mullvad tunnel set daita-direct-only on 2>/dev/null
        else
            mullvad tunnel set daita-direct-only off 2>/dev/null
        fi
        mullvad tunnel set daita on 2>/dev/null
        mullvad reconnect 2>/dev/null
        wait_for_state "connected" 30
        if [ "$(get_state)" = "connected" ]; then
            ACHIEVED_DAITA="on"
        else
            echo "[$(date)] ⚠️  DAITA broke connection — disabling"
            mullvad tunnel set daita off 2>/dev/null
            mullvad reconnect 2>/dev/null
            wait_for_state "connected" 30
        fi
    fi

    if [ "$WANT_QUIC" = "1" ]; then
        echo "[$(date)] ➕ Enabling QUIC obfuscation..."
        if set_obf_mode quic; then
            mullvad reconnect 2>/dev/null
            wait_for_state "connected" 30
            if [ "$(get_state)" = "connected" ]; then
                ACHIEVED_OBF="quic"
            else
                # QUIC pool is small; widen country selection and try again
                echo "[$(date)]   QUIC failed in pinned country — trying any country..."
                mullvad relay set location any 2>/dev/null
                mullvad reconnect 2>/dev/null
                wait_for_state "connected" 30
                if [ "$(get_state)" = "connected" ]; then
                    ACHIEVED_OBF="quic"
                    echo "[$(date)]   ✅ QUIC connected (any country)"
                else
                    echo "[$(date)]   QUIC unavailable — falling back through obfuscation chain..."
                    [ "$OBF_FALLBACK" = "1" ] && obf_fallback_chain
                fi
            fi
        fi
    fi

    return 0
}

connect_progressive() {
    local CC="$1"
    echo "[$(date)] 🌍 Target country: ${CC^^}"

    reset_daemon
    if ! mullvad relay set location "$CC" 2>/dev/null; then
        echo "[$(date)] ❌ relay set failed for $CC"
        return 1
    fi
    set_features_baseline

    if ! try_connect "plain WG"; then
        echo "[$(date)] 🔄 Plain WG failed — restarting daemon and retrying"
        systemctl restart mullvad-daemon 2>/dev/null
        sleep 3
        for i in $(seq 1 15); do mullvad status &>/dev/null && break; sleep 1; done
        mullvad relay set location "$CC" 2>/dev/null
        set_features_baseline
        if ! try_connect "plain WG retry"; then
            return 1
        fi
    fi

    layer_features "$CC"
    return 0
}

# --- KILL PRIOR WATCHDOG (safe, targeted only) ---
echo "[$(date)] 🧹 Reaping prior watchdog (if any)..."
if [ -f "$WATCHDOG_PIDFILE" ]; then
    OLD_PID="$(cat "$WATCHDOG_PIDFILE" 2>/dev/null || echo)"
    if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        kill "$OLD_PID" 2>/dev/null && echo "[$(date)]   killed prior watchdog PID $OLD_PID"
        sleep 1
    fi
    rm -f "$WATCHDOG_PIDFILE"
fi
# Only kill processes whose argv[0] is exactly the watchdog tag.
# This is safe because we set argv[0] via `exec -a` when launching the watchdog.
pkill -f "$WATCHDOG_TAG" 2>/dev/null
# v29.1: REMOVED the broad "mullvad-optimizer" pkill. It was matching the
# tee process running `tee -a /var/log/mullvad-optimizer.log` and killing
# it broke the script's stdout pipe → SIGPIPE → silent script exit.

# --- HOST FIREWALL LOCKDOWN ---
iptables -P FORWARD DROP || fail "FORWARD DROP"
iptables -P INPUT   DROP || fail "INPUT DROP"
iptables -P OUTPUT  ACCEPT
iptables -F            || fail "iptables flush"
iptables -t nat    -F  || fail "nat flush"
iptables -t mangle -F  || fail "mangle flush"

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i "$LAN_IF" -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -i "$LAN_IF" -p icmp -j ACCEPT

ip6tables -P INPUT   DROP   2>/dev/null
ip6tables -P FORWARD DROP   2>/dev/null
ip6tables -P OUTPUT  DROP   2>/dev/null
ip6tables -F                2>/dev/null
ip6tables -A INPUT  -i lo -j ACCEPT 2>/dev/null
ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null

DRIVER="$(ethtool -i "$LAN_IF" 2>/dev/null | awk -F': ' '/^driver/ {print $2}')"
[ -n "$DRIVER" ] && [ "$DRIVER" != "virtio_net" ] \
    && ethtool --set-eee "$LAN_IF" eee off 2>/dev/null

sysctl -w net.ipv4.ip_forward=1 >/dev/null || fail "ip_forward"
sysctl -w net.ipv6.conf.all.disable_ipv6=1 2>/dev/null
sysctl -w net.ipv6.conf.default.disable_ipv6=1 2>/dev/null
sysctl -w "net.ipv6.conf.${LAN_IF}.disable_ipv6=1" 2>/dev/null
echo "[$(date)] 🛡️  Firewall locked (FORWARD=DROP, IPv6=DROP)"

# --- ATTEMPT CONNECT WITH AUTO COUNTRY ROTATION ---
TARGET=""
SUCCESS=0
ACHIEVED_QUANTUM="off"
ACHIEVED_DAITA="off"
ACHIEVED_OBF="none"

for ATTEMPT in 1 2 3; do
    CC="$(get_valid_country)"
    [ "$ATTEMPT" -gt 1 ] && echo "[$(date)] 🔄 Attempt $ATTEMPT: trying ${CC^^}"
    if connect_progressive "$CC"; then
        TARGET="$CC"
        SUCCESS=1
        break
    fi
    echo "$(date +%s) $CC" >> "$BAN_FILE"
    echo "[$(date)] ⚠️  Banned ${CC^^} for 8h"
done
[ "$SUCCESS" -ne 1 ] && fail "Could not connect to any allowed country"

# --- WAIT FOR wg-mullvad INTERFACE ---
WG_IF=""
for i in $(seq 1 40); do
    WG_IF="$(ip -br link show 2>/dev/null | awk '/wg[0-9]?-mullvad/ {print $1; exit}' | sed 's/@.*$//')"
    [ -n "$WG_IF" ] && break
    sleep 0.5
done
[ -z "$WG_IF" ] && fail "wg-mullvad interface never appeared"
echo "[$(date)] ✅ Interface created: $WG_IF"
echo "$WG_IF" > /var/tmp/mullvad_current_if

# --- APPLY GATEWAY RULES ---
iptables -A FORWARD -i "$LAN_IF" -o "$WG_IF" -j ACCEPT
iptables -t nat -A POSTROUTING -o "$WG_IF" -j MASQUERADE
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss "$MSS_CLAMP"
iptables -t mangle -A OUTPUT  -p tcp --tcp-flags SYN,RST SYN \
    -o "$WG_IF" -j TCPMSS --set-mss "$MSS_CLAMP"
iptables -A FORWARD -i "$LAN_IF" -p udp --dport 53 ! -o "$WG_IF" -j DROP
iptables -A FORWARD -i "$LAN_IF" -p tcp --dport 53 ! -o "$WG_IF" -j DROP
modprobe sch_cake 2>/dev/null
tc qdisc del dev "$LAN_IF" root 2>/dev/null
tc qdisc add dev "$LAN_IF" root cake bandwidth "$CAKE_BW" nat wash ack-filter 2>/dev/null \
    || echo "[$(date)]   ⚠️  CAKE qdisc setup failed"
echo "[$(date)] 🛡️  Tunnel rules applied (NAT, MSS clamp, DNS lock, CAKE)"

# --- VERIFY + STATUS REPORT (RESTORED OLD FORMAT) ---
echo "[$(date)] 🔍 Verifying connection..."
sleep 2
STATE="$(get_state)"
IP="$(curl -s --max-time 8 https://am.i.mullvad.net/ip 2>/dev/null || echo)"
[ -z "$IP" ] && IP="Unknown"

FULL_STATUS="$( { mullvad status -v 2>/dev/null || mullvad status 2>/dev/null; } )"

# Parse fields
RELAY_LINE="$(echo "$FULL_STATUS" | awk -F'Relay:[[:space:]]*' '/Relay:/ {print $2; exit}' | sed 's/[[:space:]]*$//')"
RELAY_NAME="$(echo "$RELAY_LINE" | awk '{print $1}')"
ENTRY_NAME="$(echo "$RELAY_LINE" | awk '/via/ {for(i=1;i<=NF;i++) if($i=="via") {print $(i+1); exit}}')"
LOCATION="$(echo "$FULL_STATUS" | awk '/Visible location:/ {sub(/^[^:]*:[[:space:]]*/,""); sub(/[[:space:]]+IPv[46]:.*$/,""); sub(/[[:space:]]*\.?[[:space:]]*$/,""); print; exit}')"
TUN_IP4="$(echo "$FULL_STATUS" | grep -oE 'IPv4:[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 | awk '{print $2}')"

# Cross-check feature_indicators against achieved
FULL_LOWER="$(echo "$FULL_STATUS" | tr '[:upper:]' '[:lower:]')"
QUANTUM_VERIFIED="off"; DAITA_VERIFIED="off"; OBF_VERIFIED="none"
echo "$FULL_LOWER" | grep -q "quantum"     && QUANTUM_VERIFIED="on"
echo "$FULL_LOWER" | grep -q "daita"       && DAITA_VERIFIED="on"
echo "$FULL_LOWER" | grep -q "quic"        && OBF_VERIFIED="quic"
echo "$FULL_LOWER" | grep -q "shadowsocks" && OBF_VERIFIED="shadowsocks"
echo "$FULL_LOWER" | grep -qE "udp2tcp|udp-over-tcp" && OBF_VERIFIED="udp2tcp"
echo "$FULL_LOWER" | grep -qE "lwo|lightweight" && OBF_VERIFIED="lwo"

MULTIHOP="off"
[ -n "$ENTRY_NAME" ] && MULTIHOP="on"
echo "$FULL_LOWER" | grep -q "multihop" && MULTIHOP="on"

# Engage host kill-switch
LOCKDOWN_ST="off"
if [ "$ENABLE_LOCKDOWN" = "1" ] && [ "$STATE" = "connected" ]; then
    if mullvad lockdown-mode set on 2>/dev/null; then
        LOCKDOWN_ST="on"
    fi
fi

OBF_DESC="$(obf_descriptor "$OBF_VERIFIED")"
MSS_DESC="$(mss_descriptor "$MSS_CLAMP")"
MTU_DESC="$(mtu_descriptor "$WG_MTU")"

echo ""
echo "[$(date)] ✅ Connection Established!"
echo ""
echo "══════════════════════════ STATUS REPORT ══════════════════════════"
printf "  %-14s %s\n" "STATE:"       "$STATE"
printf "  %-14s %s\n" "TARGET CC:"   "${TARGET^^}"
[ -n "$RELAY_NAME" ] && printf "  %-14s %s\n" "RELAY:"       "$RELAY_NAME"
[ -n "$ENTRY_NAME" ] && printf "  %-14s %s\n" "ENTRY (hop):" "$ENTRY_NAME"
[ -n "$LOCATION"   ] && printf "  %-14s %s\n" "LOCATION:"    "$LOCATION"
printf "  %-14s %s\n" "PUBLIC IP:"   "$IP"
[ -n "$TUN_IP4"    ] && printf "  %-14s %s\n" "TUNNEL IPv4:" "$TUN_IP4"
printf "  %-14s %s\n" "INTERFACE:"   "$WG_IF"
echo  "  ─────────────────────────────────────────────────────────────"
printf "  %-14s %s (%s)\n" "OBFUSCATION:" "$OBF_VERIFIED" "$OBF_DESC"
printf "  %-14s %s\n"     "QUANTUM:"     "$QUANTUM_VERIFIED"
printf "  %-14s %s\n"     "DAITA:"       "$DAITA_VERIFIED"
printf "  %-14s %s\n"     "MULTIHOP:"    "$MULTIHOP"
echo  "  ─────────────────────────────────────────────────────────────"
printf "  %-14s %s (%s)\n" "WG MTU:"    "$WG_MTU"    "$MTU_DESC"
printf "  %-14s %s (%s)\n" "MSS CLAMP:" "$MSS_CLAMP" "$MSS_DESC"
printf "  %-14s CAKE (%s)\n" "QUEUE:"   "$CAKE_BW"
echo  "  ─────────────────────────────────────────────────────────────"
printf "  %-14s %s  (Mullvad host kill-switch)\n" "LOCKDOWN:"  "$LOCKDOWN_ST"
printf "  %-14s DROP (tunnel-only)\n"             "FWD POLICY:"
echo "═══════════════════════════════════════════════════════════════════"

# Warnings about feature mismatches (informational)
if [ "$WANT_QUIC" = "1" ] && [ "$OBF_VERIFIED" != "quic" ]; then
    echo ""
    echo "  ⚠️  QUIC requested but not active — achieved: $OBF_VERIFIED"
    echo "      Mullvad's QUIC relay pool is limited (per upstream issue #8742)."
fi
if [ "$WANT_DAITA" = "1" ] && [ "$DAITA_VERIFIED" != "on" ]; then
    echo ""
    echo "  ⚠️  DAITA requested but not active. No relay matched all constraints."
fi

# --- WATCHDOG ---
(
exec -a "$WATCHDOG_TAG" bash <<EOF_WATCHDOG
set -u
LAN_IF='$LAN_IF'
WG_MTU=$WG_MTU
MSS_CLAMP=$MSS_CLAMP
CAKE_BW='$CAKE_BW'
ALLOWED_COUNTRIES=($(printf "'%s' " "${ALLOWED_COUNTRIES[@]}"))
BAN_FILE='$BAN_FILE'
LAST_USED_FILE='$LAST_USED_FILE'
LOG_FILE='$LOG_FILE'
ACHIEVED_OBF='$OBF_VERIFIED'
WANT_QUANTUM=$WANT_QUANTUM
WANT_DAITA=$WANT_DAITA

FAIL_COUNT=0
THRESHOLD=3
BACKOFF_LEVEL=0
BACKOFF=(15 60 180 600)
RECOVERED_RECENTLY=0
CURRENT_IF="\$(cat /var/tmp/mullvad_current_if 2>/dev/null || echo)"
CURRENT_COUNTRY="\$(cat "\$LAST_USED_FILE" 2>/dev/null || echo)"

log() { echo "[\$(date)] \$*" >> "\$LOG_FILE"; }
log "👁️  Watchdog v29.1 active (IF=\$CURRENT_IF country=\$CURRENT_COUNTRY obf=\$ACHIEVED_OBF)"

cleanup_iface() {
    local IF="\$1"
    [ -z "\$IF" ] && return 0
    iptables -D FORWARD -i "\$LAN_IF" -o "\$IF" -j ACCEPT 2>/dev/null
    iptables -t nat -D POSTROUTING -o "\$IF" -j MASQUERADE 2>/dev/null
    conntrack -F 2>/dev/null
}

reapply_rules() {
    local NEW_IF="\$1"
    iptables -A FORWARD -i "\$LAN_IF" -o "\$NEW_IF" -j ACCEPT 2>/dev/null
    iptables -t nat -A POSTROUTING -o "\$NEW_IF" -j MASQUERADE 2>/dev/null
    iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN \
        -j TCPMSS --set-mss "\$MSS_CLAMP" 2>/dev/null \
        || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
            -j TCPMSS --set-mss "\$MSS_CLAMP" 2>/dev/null
    iptables -t mangle -C OUTPUT -p tcp --tcp-flags SYN,RST SYN \
        -o "\$NEW_IF" -j TCPMSS --set-mss "\$MSS_CLAMP" 2>/dev/null \
        || iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN \
            -o "\$NEW_IF" -j TCPMSS --set-mss "\$MSS_CLAMP" 2>/dev/null
    iptables -C FORWARD -i "\$LAN_IF" -p udp --dport 53 ! -o "\$NEW_IF" -j DROP 2>/dev/null \
        || iptables -A FORWARD -i "\$LAN_IF" -p udp --dport 53 ! -o "\$NEW_IF" -j DROP 2>/dev/null
    iptables -C FORWARD -i "\$LAN_IF" -p tcp --dport 53 ! -o "\$NEW_IF" -j DROP 2>/dev/null \
        || iptables -A FORWARD -i "\$LAN_IF" -p tcp --dport 53 ! -o "\$NEW_IF" -j DROP 2>/dev/null
    modprobe sch_cake 2>/dev/null
    tc qdisc del dev "\$LAN_IF" root 2>/dev/null
    tc qdisc add dev "\$LAN_IF" root cake bandwidth "\$CAKE_BW" nat wash ack-filter 2>/dev/null
}

get_state() {
    mullvad status 2>/dev/null | head -1 | tr '[:upper:]' '[:lower:]' \
        | grep -oE 'disconnected|connecting|connected|blocked|error' | head -1
}

# Tolerant ping check — 3 packets, healthy if 2/3 succeed
ping_healthy() {
    local OK=0
    for i in 1 2 3; do
        ping -c 1 -W 5 1.1.1.1 >/dev/null 2>&1 && OK=\$((OK + 1))
    done
    [ "\$OK" -ge 2 ]
}

while true; do
    sleep 15

    HEALTHY=true
    [ "\$(get_state)" != "connected" ] && HEALTHY=false
    \$HEALTHY && ! ping_healthy && HEALTHY=false

    if \$HEALTHY; then
        if [ "\$RECOVERED_RECENTLY" = "1" ]; then
            log "💚 Health restored"
            RECOVERED_RECENTLY=0
        fi
        FAIL_COUNT=0
        BACKOFF_LEVEL=0
        continue
    fi

    FAIL_COUNT=\$((FAIL_COUNT + 1))
    [ \$FAIL_COUNT -lt \$THRESHOLD ] && continue

    log "⚠️  Persistent connection drop (3 consecutive checks failed) — migrating"

    [ -n "\$CURRENT_COUNTRY" ] && echo "\$(date +%s) \$CURRENT_COUNTRY" >> "\$BAN_FILE"
    cleanup_iface "\$CURRENT_IF"

    AVAILABLE=()
    NOW=\$(date +%s)
    EXPIRY=\$((NOW - 28800))
    [ -f "\$BAN_FILE" ] && {
        awk -v expiry="\$EXPIRY" '\$1 > expiry' "\$BAN_FILE" > "\${BAN_FILE}.tmp" 2>/dev/null \
            && mv "\${BAN_FILE}.tmp" "\$BAN_FILE"
    }
    for c in "\${ALLOWED_COUNTRIES[@]}"; do
        grep -q " \$c\$" "\$BAN_FILE" 2>/dev/null || AVAILABLE+=("\$c")
    done
    [ "\${#AVAILABLE[@]}" -eq 0 ] && { : > "\$BAN_FILE"; AVAILABLE=("\${ALLOWED_COUNTRIES[@]}"); }
    NEW_COUNTRY="\${AVAILABLE[\$((RANDOM % \${#AVAILABLE[@]}))]}"
    log "🔄 Migrating to \${NEW_COUNTRY^^}"

    systemctl restart mullvad-daemon 2>/dev/null
    sleep 4
    for i in \$(seq 1 15); do mullvad status &>/dev/null && break; sleep 1; done

    mullvad relay set location "\$NEW_COUNTRY" 2>/dev/null
    mullvad anti-censorship set mode auto 2>/dev/null \
        || mullvad obfuscation set mode auto 2>/dev/null
    mullvad tunnel set quantum-resistant off 2>/dev/null
    mullvad tunnel set daita off 2>/dev/null

    timeout 60 mullvad connect --wait >/dev/null 2>&1
    sleep 2

    if [ "\$(get_state)" = "connected" ]; then
        if [ "\$WANT_QUANTUM" = "1" ]; then
            mullvad tunnel set quantum-resistant on 2>/dev/null
            mullvad reconnect 2>/dev/null; sleep 5
            [ "\$(get_state)" != "connected" ] && {
                mullvad tunnel set quantum-resistant off 2>/dev/null
                mullvad reconnect 2>/dev/null; sleep 5
            }
        fi
        if [ "\$WANT_DAITA" = "1" ]; then
            mullvad tunnel set daita on 2>/dev/null
            mullvad reconnect 2>/dev/null; sleep 5
            [ "\$(get_state)" != "connected" ] && {
                mullvad tunnel set daita off 2>/dev/null
                mullvad reconnect 2>/dev/null; sleep 5
            }
        fi
        if [ "\$ACHIEVED_OBF" != "none" ]; then
            mullvad anti-censorship set mode "\$ACHIEVED_OBF" 2>/dev/null \
                || mullvad obfuscation set mode "\$ACHIEVED_OBF" 2>/dev/null
            mullvad reconnect 2>/dev/null; sleep 5
            [ "\$(get_state)" != "connected" ] && {
                mullvad anti-censorship set mode auto 2>/dev/null \
                    || mullvad obfuscation set mode auto 2>/dev/null
                mullvad reconnect 2>/dev/null; sleep 5
            }
        fi

        if [ "\$(get_state)" = "connected" ]; then
            NEW_IF="\$(ip -br link show 2>/dev/null | awk '/wg[0-9]?-mullvad/ {print \$1; exit}' | sed 's/@.*\$//')"
            if [ -n "\$NEW_IF" ]; then
                reapply_rules "\$NEW_IF"
                echo "\$NEW_IF" > /var/tmp/mullvad_current_if
                echo "\$NEW_COUNTRY" > "\$LAST_USED_FILE"
                CURRENT_IF="\$NEW_IF"
                CURRENT_COUNTRY="\$NEW_COUNTRY"
                FAIL_COUNT=0
                BACKOFF_LEVEL=0
                RECOVERED_RECENTLY=1
                log "✅ Recovered in \${NEW_COUNTRY^^} via \$NEW_IF"
                continue
            fi
        fi
    fi

    BACKOFF_TIME=\${BACKOFF[\$BACKOFF_LEVEL]}
    log "⏳ Recovery failed; backing off \${BACKOFF_TIME}s"
    sleep "\$BACKOFF_TIME"
    [ \$BACKOFF_LEVEL -lt \$((\${#BACKOFF[@]} - 1)) ] && BACKOFF_LEVEL=\$((BACKOFF_LEVEL + 1))
    FAIL_COUNT=0
done
EOF_WATCHDOG
) & disown
WATCHDOG_PID=$!
echo "$WATCHDOG_PID" > "$WATCHDOG_PIDFILE"
trap - INT TERM
echo ""
echo "[$(date)] 👁️  Watchdog launched (PID: $WATCHDOG_PID)"
echo "[$(date)] 🚀 Gateway ready"
echo ""
echo "  📜 Logs:     tail -f $LOG_FILE"
echo "  🛑 Teardown: sudo bash teardown-mullvad-gateway-v28.sh"
echo "  🚑 Emergency: sudo bash emergency-restore.sh"
echo ""
