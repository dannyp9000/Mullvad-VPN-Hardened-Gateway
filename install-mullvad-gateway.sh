#!/bin/bash
# ==============================================================================
#   MULLVAD EMERGENCY NETWORK RESTORE
#
#   When teardown didn't restore internet, run this. It does what teardown v26
#   should have done but didn't:
#     - Stops mullvad-daemon (forces it to clear its nftables rules)
#     - Deletes any leftover wg-mullvad interface
#     - Removes Mullvad's policy-routing rules (fwmark 0x6d6f6c65)
#     - Flushes BOTH iptables AND nftables
#     - Restores default route if it's missing
#     - Restarts the daemon so you can connect cleanly next time
#
#   Use:  sudo bash emergency-restore.sh
# ==============================================================================

set -u

if [ "$(id -u)" -ne 0 ]; then echo "❌ Must run as root"; exit 1; fi

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  🚑 EMERGENCY NETWORK RESTORE"
echo "══════════════════════════════════════════════════════════════"

# 1. Kill watchdog
echo ""
echo "▸ Killing any watchdog..."
pkill -f mullvad_gateway_watchdog 2>/dev/null && echo "  ✅ Watchdog killed" || echo "  (none running)"
rm -f /var/run/mullvad-gateway-watchdog.pid

# 2. Disconnect mullvad and poll for disconnected state
echo ""
echo "▸ Disconnecting Mullvad (and waiting for state)..."
if command -v mullvad &>/dev/null; then
    mullvad lockdown-mode set off 2>/dev/null || true
    mullvad disconnect 2>/dev/null || true
    # POLL for state to actually be disconnected
    for i in {1..15}; do
        STATE="$(mullvad status 2>/dev/null | head -1 | tr '[:upper:]' '[:lower:]')"
        case "$STATE" in
            *disconnected*) echo "  ✅ Daemon: disconnected"; break ;;
            *) sleep 1 ;;
        esac
        [ "$i" -eq 15 ] && echo "  ⚠️  Daemon never reached disconnected (will force-stop)"
    done
fi

# 3. Stop mullvad-daemon — this is what forces it to drop its nftables rules
echo ""
echo "▸ Stopping mullvad-daemon (clears its nftables rules)..."
if systemctl stop mullvad-daemon 2>/dev/null; then
    echo "  ✅ mullvad-daemon stopped"
else
    echo "  ⚠️  Could not stop mullvad-daemon"
fi
sleep 1

# 4. Force-delete any leftover wg-mullvad interface (known kernel-netlink bug)
echo ""
echo "▸ Removing leftover wg-mullvad interfaces..."
REMOVED=0
for IF in $(ip -br link show 2>/dev/null | awk '/wg[0-9]?-mullvad/ {print $1}' | sed 's/@.*$//'); do
    if ip link delete "$IF" 2>/dev/null; then
        echo "  ✅ Deleted $IF"
        REMOVED=$((REMOVED + 1))
    fi
done
[ $REMOVED -eq 0 ] && echo "  (none found)"

# 5. Remove Mullvad's policy-routing rules (fwmark 0x6d6f6c65)
echo ""
echo "▸ Removing Mullvad policy-routing rules..."
RULE_COUNT=0
# Mullvad uses fwmark 0x6d6f6c65 — strip every rule that mentions it
while ip rule show 2>/dev/null | grep -q "0x6d6f6c65"; do
    LINE="$(ip rule show | grep -m1 '0x6d6f6c65')"
    PRIO="$(echo "$LINE" | awk -F: '{print $1}' | tr -d ' ')"
    if [ -n "$PRIO" ]; then
        ip rule del prio "$PRIO" 2>/dev/null && RULE_COUNT=$((RULE_COUNT + 1)) || break
    else
        break
    fi
done
[ $RULE_COUNT -gt 0 ] && echo "  ✅ Removed $RULE_COUNT policy rules" || echo "  (none found)"

# Flush Mullvad's custom routing table (Mullvad uses table 'mullvad' in /etc/iproute2/rt_tables, or numeric)
ip route flush table mullvad 2>/dev/null || true
# Also flush any high-numbered tables that look mullvad-shaped (see chaeynz blog: 1836018789)
for T in $(ip rule show 2>/dev/null | awk -F'lookup ' '/lookup [0-9]+/ {print $2}' | awk '{print $1}' | sort -u); do
    case "$T" in
        main|default|local|0|254|255) continue ;;
    esac
    ip route flush table "$T" 2>/dev/null || true
done

# 6. Flush iptables (legacy)
echo ""
echo "▸ Flushing iptables..."
iptables -P INPUT   ACCEPT 2>/dev/null
iptables -P FORWARD ACCEPT 2>/dev/null
iptables -P OUTPUT  ACCEPT 2>/dev/null
iptables -F            2>/dev/null
iptables -t nat    -F  2>/dev/null
iptables -t mangle -F  2>/dev/null
ip6tables -P INPUT   ACCEPT 2>/dev/null
ip6tables -P FORWARD ACCEPT 2>/dev/null
ip6tables -P OUTPUT  ACCEPT 2>/dev/null
ip6tables -F            2>/dev/null
ip6tables -t nat    -F  2>/dev/null
ip6tables -t mangle -F  2>/dev/null
echo "  ✅ iptables/ip6tables flushed"

# 7. Flush nftables — TARGETED to mullvad's tables (don't kill docker/etc)
echo ""
echo "▸ Cleaning Mullvad nftables..."
if command -v nft &>/dev/null; then
    NFT_REMOVED=0
    # Mullvad's tables are typically named "mullvad" (inet) and may include "mullvad-strict-dns"
    for TABLE_LINE in $(nft list tables 2>/dev/null | grep -iE 'mullvad' || true); do
        # Each line: "table inet mullvad" — extract family and name
        FAMILY="$(echo "$TABLE_LINE" | awk '{print $2}')"
        NAME="$(echo "$TABLE_LINE" | awk '{print $3}')"
        if [ -n "$FAMILY" ] && [ -n "$NAME" ]; then
            if nft delete table "$FAMILY" "$NAME" 2>/dev/null; then
                echo "  ✅ Deleted nft table: $FAMILY $NAME"
                NFT_REMOVED=$((NFT_REMOVED + 1))
            fi
        fi
    done
    [ $NFT_REMOVED -eq 0 ] && echo "  (no mullvad nftables found — daemon stop already cleared)"
else
    echo "  (nft not installed — skipping)"
fi

# 8. Conntrack
echo ""
echo "▸ Flushing conntrack..."
if command -v conntrack &>/dev/null; then
    conntrack -F 2>/dev/null && echo "  ✅ Conntrack flushed" || echo "  (nothing to flush)"
fi

# 9. Remove CAKE qdisc
echo ""
echo "▸ Removing CAKE qdisc..."
REMOVED=0
while read -r IFACE _; do
    [ "$IFACE" = "lo" ] && continue
    if tc qdisc show dev "$IFACE" 2>/dev/null | grep -q "qdisc cake"; then
        tc qdisc del dev "$IFACE" root 2>/dev/null && {
            echo "  ✅ Removed CAKE from $IFACE"
            REMOVED=$((REMOVED + 1))
        }
    fi
done < <(ip -br link show 2>/dev/null)
[ $REMOVED -eq 0 ] && echo "  (none found)"

# 10. Re-enable IPv6
echo ""
echo "▸ Re-enabling IPv6..."
sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 && echo "  ✅ IPv6 (all) on"
sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1
for IFACE in $(ip -br link show 2>/dev/null | awk '$1 != "lo" {print $1}'); do
    sysctl -w "net.ipv6.conf.${IFACE}.disable_ipv6=0" >/dev/null 2>&1
done

# 11. State files
rm -f /var/tmp/mullvad_current_if 2>/dev/null

# 12. Verify default route exists; if not, attempt DHCP renew
echo ""
echo "▸ Verifying routing..."
if ! ip route show default | grep -q "default via"; then
    echo "  ⚠️  No default route — trying DHCP renew on each iface"
    for IFACE in $(ip -br link show 2>/dev/null | awk '$1 != "lo" && $2 == "UP" {print $1}'); do
        dhclient -r "$IFACE" 2>/dev/null
        dhclient    "$IFACE" 2>/dev/null && echo "    ✅ DHCP renewed on $IFACE"
    done
fi
ip route show default || true

# 13. Restart mullvad-daemon (so future connects work without reboot)
echo ""
echo "▸ Restarting mullvad-daemon..."
systemctl start mullvad-daemon 2>/dev/null && echo "  ✅ mullvad-daemon started" || echo "  ⚠️  failed to start"

# 14. Test
echo ""
echo "▸ Testing internet..."
if ping -c 2 -W 3 1.1.1.1 >/dev/null 2>&1; then
    echo "  ✅ Internet works (ping 1.1.1.1)"
else
    echo "  ❌ Still no internet. Possible causes:"
    echo "     - DHCP didn't get a lease — try: sudo dhclient -v eth0"
    echo "     - Default route missing — try: sudo ip route add default via <your_router_ip>"
    echo "     - Reboot is now your last resort: sudo reboot"
fi

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  RESTORE COMPLETE"
echo "══════════════════════════════════════════════════════════════"
echo ""
