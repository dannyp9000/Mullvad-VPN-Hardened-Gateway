#!/bin/bash
# ==============================================================================
#   MULLVAD GATEWAY — Teardown / Emergency Recovery (v26.0)
#
#   Reverses everything install-mullvad-gateway.sh sets up:
#     - Kills the watchdog
#     - Disables Mullvad lockdown-mode
#     - Disconnects Mullvad
#     - Resets all iptables/ip6tables policies to ACCEPT
#     - Flushes filter, nat, and mangle tables
#     - Removes the CAKE qdisc from the LAN interface
#     - Re-enables IPv6 (or leaves it alone if KEEP_IPV6_OFF=1)
#
#   Usage:
#     sudo bash teardown-mullvad-gateway.sh
#     sudo KEEP_IPV6_OFF=1 bash teardown-mullvad-gateway.sh
#
#   Safe to run multiple times. Designed to be the absolute first thing you
#   try when the gateway breaks your internet.
# ==============================================================================

set -u

WATCHDOG_PIDFILE="/var/run/mullvad-gateway-watchdog.pid"
WATCHDOG_TAG="mullvad_gateway_watchdog"
KEEP_IPV6_OFF="${KEEP_IPV6_OFF:-0}"

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  🛑 MULLVAD GATEWAY TEARDOWN  v26.0"
echo "══════════════════════════════════════════════════════════════"

if [ "$(id -u)" -ne 0 ]; then echo "❌ FAIL: Must run as root"; exit 1; fi

# --- 1. KILL WATCHDOG ---
echo ""
echo "▸ Stopping watchdog..."
if [ -f "$WATCHDOG_PIDFILE" ]; then
    PID="$(cat "$WATCHDOG_PIDFILE" 2>/dev/null || echo)"
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null && echo "  ✅ Killed PID $PID" || echo "  ⚠️  Could not kill PID $PID"
    fi
    rm -f "$WATCHDOG_PIDFILE"
fi
if pkill -f "$WATCHDOG_TAG" 2>/dev/null; then
    echo "  ✅ Killed any other $WATCHDOG_TAG processes"
else
    echo "  (no watchdog running)"
fi

# --- 2. DISABLE LOCKDOWN + DISCONNECT ---
echo ""
echo "▸ Disabling Mullvad lockdown + tunnel..."
if command -v mullvad &>/dev/null; then
    mullvad lockdown-mode set off 2>/dev/null && echo "  ✅ Lockdown OFF" || echo "  ⚠️  lockdown-mode set off failed"
    mullvad disconnect 2>/dev/null && echo "  ✅ Disconnected" || echo "  (already disconnected)"
else
    echo "  (mullvad CLI not found — skipping)"
fi

# --- 3. RESET IPTABLES ---
echo ""
echo "▸ Resetting iptables..."
iptables  -P INPUT   ACCEPT 2>/dev/null && echo "  ✅ INPUT  policy ACCEPT"  || echo "  ⚠️  INPUT  policy"
iptables  -P FORWARD ACCEPT 2>/dev/null && echo "  ✅ FORWARD policy ACCEPT" || echo "  ⚠️  FORWARD policy"
iptables  -P OUTPUT  ACCEPT 2>/dev/null && echo "  ✅ OUTPUT policy ACCEPT"  || echo "  ⚠️  OUTPUT policy"
iptables  -F            2>/dev/null && echo "  ✅ Filter table flushed"
iptables  -t nat    -F  2>/dev/null && echo "  ✅ NAT table flushed"
iptables  -t mangle -F  2>/dev/null && echo "  ✅ Mangle table flushed"

echo ""
echo "▸ Resetting ip6tables..."
if ip6tables -P INPUT ACCEPT 2>/dev/null; then
    echo "  ✅ INPUT  policy ACCEPT"
    ip6tables -P FORWARD ACCEPT 2>/dev/null && echo "  ✅ FORWARD policy ACCEPT"
    ip6tables -P OUTPUT  ACCEPT 2>/dev/null && echo "  ✅ OUTPUT policy ACCEPT"
    ip6tables -F            2>/dev/null
    ip6tables -t nat    -F  2>/dev/null
    ip6tables -t mangle -F  2>/dev/null
else
    echo "  (no ip6tables)"
fi

# --- 4. CLEAR CONNTRACK ---
echo ""
echo "▸ Clearing conntrack..."
if command -v conntrack &>/dev/null; then
    conntrack -F 2>/dev/null && echo "  ✅ Conntrack flushed" || echo "  (nothing to flush)"
fi

# --- 5. REMOVE CAKE QDISC ---
echo ""
echo "▸ Removing CAKE qdisc from interfaces..."
REMOVED=0
while read -r IFACE _; do
    if [ "$IFACE" = "lo" ]; then continue; fi
    if tc qdisc show dev "$IFACE" 2>/dev/null | grep -q "qdisc cake"; then
        if tc qdisc del dev "$IFACE" root 2>/dev/null; then
            echo "  ✅ Removed CAKE from $IFACE"
            REMOVED=$((REMOVED + 1))
        fi
    fi
done < <(ip -br link show 2>/dev/null)
if [ $REMOVED -eq 0 ]; then echo "  (no CAKE qdiscs found)"; fi

# --- 6. RESTORE IPv6 (optional) ---
echo ""
if [ "$KEEP_IPV6_OFF" = "1" ]; then
    echo "▸ Leaving IPv6 disabled (KEEP_IPV6_OFF=1)"
else
    echo "▸ Re-enabling IPv6..."
    sysctl -w net.ipv6.conf.all.disable_ipv6=0 2>/dev/null \
        && echo "  ✅ IPv6 re-enabled (all)" || echo "  ⚠️  Could not re-enable IPv6"
    sysctl -w net.ipv6.conf.default.disable_ipv6=0 2>/dev/null || true
    # Re-enable on every present interface
    for IFACE in $(ip -br link show 2>/dev/null | awk '$1 != "lo" {print $1}'); do
        sysctl -w "net.ipv6.conf.${IFACE}.disable_ipv6=0" 2>/dev/null || true
    done
fi

# --- 7. STATE FILES ---
echo ""
echo "▸ Cleaning state files..."
rm -f /var/tmp/mullvad_current_if 2>/dev/null && echo "  ✅ Removed /var/tmp/mullvad_current_if"
# Leave banlist + last_gw alone — they're useful history if you re-run setup.

# --- DONE ---
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  ✅ TEARDOWN COMPLETE"
echo ""
echo "  Verify internet:"
echo "     ping -c 3 1.1.1.1"
echo ""
echo "  To re-enable the gateway:"
echo "     sudo bash install-mullvad-gateway.sh"
echo "══════════════════════════════════════════════════════════════"
echo ""
