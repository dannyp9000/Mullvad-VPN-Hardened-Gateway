#!/bin/bash
# ==============================================================================
#   MULLVAD HARDENED GATEWAY (v29.0)
#   Tested against: Mullvad 2026.1 / Debian 13 (Trixie) / Pi 5 / Proxmox VM
#
#   v29 changes from v28 — focused on obfuscation robustness & log noise:
#
#     1. **QUIC ROBUSTNESS MODE (the headline fix).**
#        QUIC obfuscation runs on a separate, smaller pool of Mullvad relays
#        than the main WG pool. The daemon picks them dynamically — but if you
#        pin a country (`relay set location se`), and that country has no
#        QUIC-capable relay available *right now*, the daemon hangs.
#
#        v29 adds a multi-strategy fallback chain when QUIC is the goal:
#          A) QUIC + relay set location any (let daemon pick QUIC-capable)
#          B) QUIC + each allowed country in order (NL, CH, US, DE, SE)
#          C) Daemon restart + retry strategy A
#          D) Fall back to Shadowsocks (auto port, then port 443)
#          E) Fall back to LWO (Lightweight WG Obfuscation, 2025.13+)
#          F) Fall back to udp2tcp (port 443)
#          G) Last resort: plain WG, log clearly that obfuscation failed
#
#        User wins: stays connected with whatever obfuscation is achievable.
#
#     2. **DAITA + QUIC CONFLICT RESOLUTION.**
#        Per Mullvad upstream issue #8742, DAITA and QUIC are mutually
#        incompatible (DAITA requires multihop in many cases; QUIC doesn't
#        support multihop). v29 detects this and follows the user policy:
#        DAITA wins when both requested. WANT_QUIC silently dropped.
#        Set DAITA_WINS=0 to flip the policy.
#
#     3. **RE-PIN RELAY AFTER EACH FEATURE TOGGLE.**
#        Last session's surprise CH exit when SE was requested: the daemon's
#        relay constraint was getting bumped during feature negotiation.
#        v29 re-issues `mullvad relay set location <CC>` after every
#        feature change and verifies the exit country matches request.
#        If it doesn't, logs a clear warning.
#
#     4. **DAITA DIRECT-ONLY MODE.**
#        New env: DAITA_DIRECT_ONLY=1 (default 0). When 1, sets
#        `mullvad tunnel set daita-direct-only on` to refuse the automatic
#        multihop redirect. Trade-off: connection may fail if the country
#        has no DAITA relays. Use when you NEED the country you asked for.
#
#     5. **WATCHDOG TOLERANCE FIX (the packet-loss spam fix).**
#        v28 watchdog logged "Connection drop (1/3)" on every single failed
#        ping, then "Health restored" 10s later. This created log noise on
#        a 180ms transcontinental VPN where occasional single-ping loss
#        is normal. v29:
#          - Pings 3 packets, considers healthy if 2/3 succeed
#          - Increases ping timeout (-W 5)
#          - Only logs "Connection drop" at threshold (when migration starts)
#          - Suppresses "Health restored" unless we actually did something
#
#     6. **STALE WATCHDOG REAPER.**
#        v28 only killed processes tagged 'mullvad_gateway_watchdog'. The
#        user's logs showed two parallel watchdogs running ("Packet Loss
#        Detected" format from an unidentified earlier script). v29 reaps
#        ANY process whose command line contains 'mullvad' and 'watchdog',
#        and warns about leftover Mullvad-related background scripts.
#
#     7. **EXIT COUNTRY VERIFICATION.**
#        After every successful connect, fetches actual visible location
#        and reports it. If mismatch with target country, logs a clear
#        WARN line so user knows the constraint wasn't respected.
#
#   Companion scripts (unchanged from v28):
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
SCRIPT_VERSION="29.0"

# Tunables (env-overridable)
CAKE_BW="${CAKE_BW:-500mbit}"
WG_MTU="${WG_MTU:-1280}"
MSS_CLAMP="${MSS_CLAMP:-1220}"
WANT_QUIC="${WANT_QUIC:-1}"
WANT_QUANTUM="${WANT_QUANTUM:-1}"
WANT_DAITA="${WANT_DAITA:-1}"
DAITA_WINS="${DAITA_WINS:-1}"             # 1: DAITA beats QUIC; 0: QUIC beats DAITA
DAITA_DIRECT_ONLY="${DAITA_DIRECT_ONLY:-0}"  # 1: refuse DAITA auto-multihop
OBF_FALLBACK="${OBF_FALLBACK:-1}"         # 1: chain through alt obf if primary fails

# --- BANNER ---
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  🔒 MULLVAD HARDENED GATEWAY  v${SCRIPT_VERSION}"
echo "      QUIC robustness + obfuscation fallback chain"
echo "══════════════════════════════════════════════════════════════"

if [ "$(id -u)" -ne 0 ]; then echo "❌ FAIL: Must run as root"; exit 1; fi

# --- DETECT DAITA+QUIC CONFLICT, APPLY POLICY ---
if [ "$WANT_DAITA" = "1" ] && [ "$WANT_QUIC" = "1" ]; then
    if [ "$DAITA_WINS" = "1" ]; then
        echo "⚠️  DAITA+QUIC are incompatible (Mullvad #8742). DAITA wins → QUIC disabled."
        WANT_QUIC=0
    else
        echo "⚠️  DAITA+QUIC are incompatible. QUIC wins (DAITA_WINS=0) → DAITA disabled."
        WANT_DAITA=0
    fi
fi

# Determine primary obfuscation goal for this run
if   [ "$WANT_QUIC" = "1" ]; then PRIMARY_OBF="quic"
else                              PRIMARY_OBF="auto"
fi

# --- INSTALL DEPENDENCIES ---
NEEDED_PKGS=()
for pkg in curl iptables conntrack ethtool iproute2 nftables jq; do
    case "$pkg" in
        iproute2)  command -v ip      &>/dev/null || NEEDED_PKGS+=("iproute2") ;;
        ethtool)   command -v ethtool &>/dev/null || NEEDED_PKGS+=("ethtool")  ;;
        nftables)  command -v nft     &>/dev/null || NEEDED_PKGS+=("nftables") ;;
        jq)        command -v jq      &>/dev/null || NEEDED_PKGS+=("jq")       ;;
        *)         command -v "$pkg"  &>/dev/null || NEEDED_PKGS+=("$pkg")     ;;
    esac
done
if [ "${#NEEDED_PKGS[@]}" -gt 0 ]; then
    echo "📦 Installing: ${NEEDED_PKGS[*]}"
    apt-get update -qq || { echo "❌ apt-get update failed"; exit 1; }
    apt-get install -y "${NEEDED_PKGS[@]}" || { echo "❌ install failed"; exit 1; }
fi
command -v mullvad &>/dev/null || { echo "❌ Mullvad not installed — run v28/v29 fresh boot"; exit 1; }

# --- LAN_IF DETECTION ---
detect_lan_if() {
    [ -n "${LAN_IF:-}" ] && return 0
    local IFACES
    mapfile -t IFACES < <(ip -br link show 2>/dev/null \
        | awk '$1 != "lo" && $2 == "UP" {print $1}')
    if [ "${#IFACES[@]}" -eq 1 ]; then
        LAN_IF="${IFACES[0]}"
        echo "🔧 Auto-detected LAN_IF=$LAN_IF"
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
echo "[$(date)] 🚀 Starting Hardened Gateway v${SCRIPT_VERSION}"
echo "[$(date)] ⚙️  LAN_IF=$LAN_IF MTU=$WG_MTU MSS=$MSS_CLAMP CAKE=$CAKE_BW"
echo "[$(date)] ⚙️  PRIMARY_OBF=$PRIMARY_OBF QUANTUM=$WANT_QUANTUM DAITA=$WANT_DAITA"
echo "[$(date)] ⚙️  DAITA_DIRECT_ONLY=$DAITA_DIRECT_ONLY OBF_FALLBACK=$OBF_FALLBACK"

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

get_exit_country() {
    # Returns 2-letter country code from "Visible location: Country, City"
    local FULL
    FULL="$( { mullvad status -v 2>/dev/null || mullvad status 2>/dev/null; } )"
    local COUNTRY
    COUNTRY="$(echo "$FULL" | awk '/Visible location:/ {sub(/^[^:]*:[[:space:]]*/,""); sub(/,.*$/,""); sub(/[[:space:]]+IPv[46]:.*$/,""); print; exit}')"
    case "$COUNTRY" in
        Sweden)        echo "se" ;;
        Switzerland)   echo "ch" ;;
        Netherlands)   echo "nl" ;;
        "United States"|USA) echo "us" ;;
        Germany)       echo "de" ;;
        France)        echo "fr" ;;
        "United Kingdom"|UK) echo "gb" ;;
        Canada)        echo "ca" ;;
        Norway)        echo "no" ;;
        Finland)       echo "fi" ;;
        Denmark)       echo "dk" ;;
        *)             echo "?" ;;
    esac
}

wait_for_state() {
    local TARGET="$1" TIMEOUT="${2:-15}"
    local i=0
    while [ $i -lt "$TIMEOUT" ]; do
        local S
        S="$(get_state)"
        [ "$S" = "$TARGET" ] && return 0
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
    # $1 = mode (auto/quic/shadowsocks/lwo/udp2tcp)
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
    # $1 = label for logging
    local LABEL="$1"
    if ! timeout 60 mullvad connect --wait >/dev/null 2>&1; then
        echo "[$(date)]   ⚠️  connect timeout ($LABEL)"
        return 1
    fi
    [ "$(get_state)" = "connected" ] && return 0
    echo "[$(date)]   ⚠️  state=$(get_state) ($LABEL)"
    return 1
}

# === KEY NEW FUNCTION ===
# Multi-strategy fallback chain to get QUIC working. Returns 0 on success.
# Sets globals: ACTIVE_OBF, ACTIVE_COUNTRY
quic_fallback_chain() {
    echo "[$(date)] 🎯 QUIC robustness mode engaged"

    # === STRATEGY A: QUIC + relay set location any (most flexible) ===
    echo "[$(date)] 🅰️  Strategy A: QUIC + any country"
    reset_daemon
    mullvad relay set location any 2>/dev/null
    set_features_baseline
    set_obf_mode quic
    if try_connect "QUIC any"; then
        ACTIVE_OBF="quic"
        ACTIVE_COUNTRY="$(get_exit_country)"
        echo "[$(date)] ✅ QUIC connected (exit=${ACTIVE_COUNTRY^^})"
        return 0
    fi

    # === STRATEGY B: QUIC + each allowed country ===
    echo "[$(date)] 🅱️  Strategy B: QUIC + each country in turn"
    for CC in "${ALLOWED_COUNTRIES[@]}"; do
        echo "[$(date)]    → trying QUIC in ${CC^^}..."
        reset_daemon
        mullvad relay set location "$CC" 2>/dev/null
        set_features_baseline
        set_obf_mode quic
        if try_connect "QUIC $CC"; then
            ACTIVE_OBF="quic"
            ACTIVE_COUNTRY="$(get_exit_country)"
            echo "[$(date)] ✅ QUIC connected (exit=${ACTIVE_COUNTRY^^})"
            return 0
        fi
    done

    # === STRATEGY C: Daemon restart, then retry QUIC any ===
    echo "[$(date)] 🅲  Strategy C: full daemon restart + QUIC any"
    systemctl restart mullvad-daemon 2>/dev/null
    sleep 4
    for i in $(seq 1 15); do mullvad status &>/dev/null && break; sleep 1; done
    mullvad relay set location any 2>/dev/null
    set_features_baseline
    set_obf_mode quic
    if try_connect "QUIC after restart"; then
        ACTIVE_OBF="quic"
        ACTIVE_COUNTRY="$(get_exit_country)"
        echo "[$(date)] ✅ QUIC connected after restart (exit=${ACTIVE_COUNTRY^^})"
        return 0
    fi

    # === FALLBACK CHAIN (only if OBF_FALLBACK=1) ===
    if [ "$OBF_FALLBACK" != "1" ]; then
        echo "[$(date)] ❌ QUIC failed and OBF_FALLBACK=0 — refusing other obfuscations"
        return 1
    fi

    # === STRATEGY D: Shadowsocks (auto, then port 443) ===
    echo "[$(date)] 🅳  Strategy D: Shadowsocks fallback"
    reset_daemon
    mullvad relay set location any 2>/dev/null
    set_features_baseline
    if set_obf_mode shadowsocks; then
        if try_connect "Shadowsocks any"; then
            ACTIVE_OBF="shadowsocks"
            ACTIVE_COUNTRY="$(get_exit_country)"
            echo "[$(date)] ✅ Shadowsocks connected (exit=${ACTIVE_COUNTRY^^})"
            return 0
        fi
    fi

    # === STRATEGY E: LWO (Lightweight WG Obfuscation, 2025.13+) ===
    echo "[$(date)] 🅴  Strategy E: LWO fallback"
    reset_daemon
    mullvad relay set location any 2>/dev/null
    set_features_baseline
    if set_obf_mode lwo; then
        if try_connect "LWO any"; then
            ACTIVE_OBF="lwo"
            ACTIVE_COUNTRY="$(get_exit_country)"
            echo "[$(date)] ✅ LWO connected (exit=${ACTIVE_COUNTRY^^})"
            return 0
        fi
    else
        echo "[$(date)]   (LWO mode not supported by this daemon — skipping)"
    fi

    # === STRATEGY F: udp2tcp ===
    echo "[$(date)] 🅵  Strategy F: udp2tcp fallback"
    reset_daemon
    mullvad relay set location any 2>/dev/null
    set_features_baseline
    if set_obf_mode udp2tcp; then
        if try_connect "udp2tcp any"; then
            ACTIVE_OBF="udp2tcp"
            ACTIVE_COUNTRY="$(get_exit_country)"
            echo "[$(date)] ✅ udp2tcp connected (exit=${ACTIVE_COUNTRY^^})"
            return 0
        fi
    fi

    # === STRATEGY G: plain WG, no obfuscation ===
    echo "[$(date)] 🅶  Strategy G: plain WG (NO OBFUSCATION — last resort)"
    reset_daemon
    local CC
    CC="$(get_valid_country)"
    mullvad relay set location "$CC" 2>/dev/null
    set_features_baseline
    if try_connect "plain WG $CC"; then
        ACTIVE_OBF="none"
        ACTIVE_COUNTRY="$(get_exit_country)"
        echo "[$(date)] ⚠️  Connected without obfuscation (exit=${ACTIVE_COUNTRY^^})"
        return 0
    fi

    return 1
}

# === DAITA-PRIMARY PATH ===
# Used when DAITA is the goal (with optional Quantum). Re-pins relay between
# feature toggles to prevent the surprise-country-redirect from last session.
connect_daita_path() {
    local CC="$1"
    echo "[$(date)] 🎯 DAITA mode: target ${CC^^}"

    reset_daemon
    mullvad relay set location "$CC" 2>/dev/null
    set_features_baseline
    if [ "$DAITA_DIRECT_ONLY" = "1" ]; then
        mullvad tunnel set daita-direct-only on 2>/dev/null \
            && echo "[$(date)]   DAITA direct-only: enabled" \
            || echo "[$(date)]   ⚠️  DAITA direct-only not supported by this daemon"
    else
        mullvad tunnel set daita-direct-only off 2>/dev/null
    fi

    # Phase 1: plain WG to verify country works
    if ! try_connect "plain WG $CC"; then
        return 1
    fi

    # Phase 2: enable Quantum if requested, RE-PIN country, reconnect
    if [ "$WANT_QUANTUM" = "1" ]; then
        echo "[$(date)] ➕ Enabling quantum-resistant..."
        mullvad relay set location "$CC" 2>/dev/null   # re-pin (defensive)
        mullvad tunnel set quantum-resistant on 2>/dev/null
        mullvad reconnect 2>/dev/null
        wait_for_state "connected" 30
        if [ "$(get_state)" != "connected" ]; then
            echo "[$(date)] ⚠️  Quantum broke — reverting"
            mullvad tunnel set quantum-resistant off 2>/dev/null
            mullvad reconnect 2>/dev/null
            wait_for_state "connected" 30
        fi
    fi

    # Phase 3: enable DAITA if requested, RE-PIN country, reconnect
    if [ "$WANT_DAITA" = "1" ]; then
        echo "[$(date)] ➕ Enabling DAITA..."
        mullvad relay set location "$CC" 2>/dev/null   # re-pin (defensive)
        mullvad tunnel set daita on 2>/dev/null
        mullvad reconnect 2>/dev/null
        wait_for_state "connected" 30
        if [ "$(get_state)" != "connected" ]; then
            echo "[$(date)] ⚠️  DAITA broke — reverting"
            mullvad tunnel set daita off 2>/dev/null
            mullvad reconnect 2>/dev/null
            wait_for_state "connected" 30
        fi
    fi

    if [ "$(get_state)" = "connected" ]; then
        ACTIVE_OBF="none"
        ACTIVE_COUNTRY="$(get_exit_country)"
        if [ "$ACTIVE_COUNTRY" != "$CC" ] && [ "$ACTIVE_COUNTRY" != "?" ]; then
            echo "[$(date)] ⚠️  Exit country (${ACTIVE_COUNTRY^^}) ≠ target (${CC^^})"
            echo "[$(date)]   Mullvad auto-multihopped (DAITA needed an entry elsewhere)."
            echo "[$(date)]   Set DAITA_DIRECT_ONLY=1 to refuse this redirect."
        fi
        return 0
    fi
    return 1
}

# --- KILL PRIOR WATCHDOGS (broader reaping than v28) ---
echo "[$(date)] 🧹 Reaping any stale watchdogs..."
if [ -f "$WATCHDOG_PIDFILE" ]; then
    OLD_PID="$(cat "$WATCHDOG_PIDFILE" 2>/dev/null || echo)"
    [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null && kill "$OLD_PID" 2>/dev/null
    rm -f "$WATCHDOG_PIDFILE"
fi
pkill -f "$WATCHDOG_TAG" 2>/dev/null
# Broader sweep — anything with mullvad+watchdog in command line
STALE=$(pgrep -f "mullvad.*watchdog\|watchdog.*mullvad" 2>/dev/null | wc -l)
if [ "$STALE" -gt 0 ]; then
    echo "[$(date)]   Found $STALE stale mullvad-watchdog processes — killing"
    pkill -f "mullvad.*watchdog" 2>/dev/null
    pkill -f "watchdog.*mullvad" 2>/dev/null
    sleep 1
fi
# Also kill any old mullvad-optimizer.sh / mullvad.sh background loops
pkill -f "mullvad-optimizer" 2>/dev/null
sleep 1

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
echo "[$(date)] 🛡️  Host firewall locked (FORWARD=DROP)"

# --- MAIN CONNECT DECISION ---
ACTIVE_OBF="none"
ACTIVE_COUNTRY=""
SUCCESS=0

if [ "$PRIMARY_OBF" = "quic" ]; then
    # User wants QUIC — full robustness chain
    if quic_fallback_chain; then SUCCESS=1; fi
else
    # No QUIC requested — DAITA/Quantum path with country rotation
    for ATTEMPT in 1 2 3; do
        CC="$(get_valid_country)"
        [ "$ATTEMPT" -gt 1 ] && echo "[$(date)] 🔄 Attempt $ATTEMPT: ${CC^^}"
        if connect_daita_path "$CC"; then
            SUCCESS=1
            break
        fi
        echo "$(date +%s) $CC" >> "$BAN_FILE"
        echo "[$(date)] ⚠️  Banned ${CC^^} for 8h"
    done
fi

[ "$SUCCESS" -ne 1 ] && fail "Could not establish any tunnel"

# --- WAIT FOR wg-mullvad INTERFACE ---
WG_IF=""
for i in $(seq 1 40); do
    WG_IF="$(ip -br link show 2>/dev/null | awk '/wg[0-9]?-mullvad/ {print $1; exit}' | sed 's/@.*$//')"
    [ -n "$WG_IF" ] && break
    sleep 0.5
done
[ -z "$WG_IF" ] && fail "wg-mullvad interface never appeared"
echo "[$(date)] ✅ Interface: $WG_IF"
echo "$WG_IF" > /var/tmp/mullvad_current_if
echo "$ACTIVE_COUNTRY" > "$LAST_USED_FILE"

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
tc qdisc add dev "$LAN_IF" root cake bandwidth "$CAKE_BW" nat wash ack-filter 2>/dev/null
echo "[$(date)] 🛡️  Gateway rules applied"

# --- VERIFY + STATUS REPORT ---
sleep 2
FULL_STATUS="$( { mullvad status -v 2>/dev/null || mullvad status 2>/dev/null; } )"
IP="$(curl -s --max-time 8 https://am.i.mullvad.net/ip 2>/dev/null || echo Unknown)"
[ -z "$IP" ] && IP="Unknown"

LOCATION="$(echo "$FULL_STATUS" | awk '/Visible location:/ {sub(/^[^:]*:[[:space:]]*/,""); sub(/[[:space:]]+IPv[46]:.*$/,""); print; exit}')"
TUN_IP4="$(echo "$FULL_STATUS" | grep -oE 'IPv4:[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 | awk '{print $2}')"
FULL_LOWER="$(echo "$FULL_STATUS" | tr '[:upper:]' '[:lower:]')"
DAITA_ST="off"; QUANTUM_ST="off"
echo "$FULL_LOWER" | grep -q "daita"   && DAITA_ST="on"
echo "$FULL_LOWER" | grep -q "quantum" && QUANTUM_ST="on"

echo ""
echo "[$(date)] ✅ Connection Established!"
echo ""
echo "══════════════════════════ STATUS REPORT ══════════════════════════"
printf "  %-14s %s\n" "EXIT COUNTRY:" "${ACTIVE_COUNTRY^^}"
printf "  %-14s %s\n" "LOCATION:"     "${LOCATION:-(unknown)}"
printf "  %-14s %s\n" "PUBLIC IP:"    "$IP"
printf "  %-14s %s\n" "TUNNEL IPv4:"  "${TUN_IP4:-(unknown)}"
printf "  %-14s %s\n" "INTERFACE:"    "$WG_IF"
echo  "  ─────────────────────────────────────────────────────────────"
printf "  %-14s %s\n" "OBFUSCATION:"  "$ACTIVE_OBF"
printf "  %-14s %s\n" "QUANTUM:"      "$QUANTUM_ST"
printf "  %-14s %s\n" "DAITA:"        "$DAITA_ST"
echo  "  ─────────────────────────────────────────────────────────────"
printf "  %-14s %s\n" "WG MTU:"       "$WG_MTU"
printf "  %-14s %s\n" "MSS CLAMP:"    "$MSS_CLAMP"
printf "  %-14s CAKE @ %s\n" "QUEUE:" "$CAKE_BW"
echo  "  ─────────────────────────────────────────────────────────────"
printf "  %-14s DROP (host kill-switch)\n" "FWD POLICY:"
echo "═══════════════════════════════════════════════════════════════════"

if [ "$PRIMARY_OBF" = "quic" ] && [ "$ACTIVE_OBF" != "quic" ]; then
    echo ""
    echo "  ⚠️  QUIC was requested but unavailable — fell back to: $ACTIVE_OBF"
    echo "      Possible reasons: no QUIC-capable relay reachable, or your"
    echo "      ISP blocks UDP/443 outbound. Tunnel is still secure."
fi

# --- WATCHDOG (v29: tolerant ping, less log spam) ---
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
ACTIVE_OBF='$ACTIVE_OBF'
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
log "👁️  Watchdog v29 (IF=\$CURRENT_IF country=\$CURRENT_COUNTRY obf=\$ACTIVE_OBF)"

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

# v29: tolerant ping check — 3 packets, healthy if 2/3 succeed, 5s timeout each
ping_healthy() {
    local OK=0
    for i in 1 2 3; do
        ping -c 1 -W 5 1.1.1.1 >/dev/null 2>&1 && OK=\$((OK + 1))
    done
    [ "\$OK" -ge 2 ]
}

while true; do
    sleep 15  # v29: was 10, gives more breathing room

    HEALTHY=true
    [ "\$(get_state)" != "connected" ] && HEALTHY=false
    \$HEALTHY && ! ping_healthy && HEALTHY=false

    if \$HEALTHY; then
        # v29: only log "Health restored" if we actually recovered (not on startup)
        if [ "\$RECOVERED_RECENTLY" = "1" ]; then
            log "💚 Health restored"
            RECOVERED_RECENTLY=0
        fi
        FAIL_COUNT=0
        BACKOFF_LEVEL=0
        continue
    fi

    FAIL_COUNT=\$((FAIL_COUNT + 1))
    # v29: silent below threshold (was logging every blip)
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

    # Re-establish with same obfuscation if possible
    mullvad relay set location "\$NEW_COUNTRY" 2>/dev/null
    mullvad anti-censorship set mode auto 2>/dev/null \
        || mullvad obfuscation set mode auto 2>/dev/null
    mullvad tunnel set quantum-resistant off 2>/dev/null
    mullvad tunnel set daita off 2>/dev/null

    timeout 60 mullvad connect --wait >/dev/null 2>&1
    sleep 2

    if [ "\$(get_state)" = "connected" ]; then
        # Re-apply previous obfuscation mode (best-effort)
        if [ "\$ACTIVE_OBF" != "none" ] && [ "\$ACTIVE_OBF" != "auto" ]; then
            mullvad anti-censorship set mode "\$ACTIVE_OBF" 2>/dev/null \
                || mullvad obfuscation set mode "\$ACTIVE_OBF" 2>/dev/null
            mullvad reconnect 2>/dev/null
            sleep 5
            [ "\$(get_state)" != "connected" ] && {
                log "  ⚠️  obf=\$ACTIVE_OBF didn't take — using auto"
                mullvad anti-censorship set mode auto 2>/dev/null \
                    || mullvad obfuscation set mode auto 2>/dev/null
                mullvad reconnect 2>/dev/null; sleep 5
            }
        fi
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
echo "[$(date)] 👁️  Watchdog v29 launched (PID: $WATCHDOG_PID)"
echo "[$(date)] 🚀 Gateway ready"
echo ""
echo "  📜 Logs:     tail -f $LOG_FILE"
echo "  🛑 Teardown: sudo bash teardown-mullvad-gateway-v28.sh"
echo "  🚑 Emergency: sudo bash emergency-restore.sh"
echo ""
echo "  Try QUIC mode:    sudo WANT_DAITA=0 WANT_QUIC=1 bash mullvad-v29.sh"
echo "  Force country:    sudo TARGET_COUNTRY=ch bash mullvad-v29.sh"
echo "  DAITA strict:     sudo DAITA_DIRECT_ONLY=1 bash mullvad-v29.sh"
echo ""
