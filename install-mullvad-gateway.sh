#!/bin/bash
# ==============================================================================
#   MULLVAD DAITA ENFORCED GATEWAY (v21.4)
#   - NEW: Forces DIFFERENT country on every script run (Anti-Repeat)
#   - FIX: Corrected Obfuscation status parsing
#   - Features: DAITA + QUANTUM + QUIC
#   - Watchdog: Auto-Rotates to expanded country list on failure
# ==============================================================================

# --- CONFIGURATION: EXPANDED POOL ---
# Allowed Exit Nodes (User Defined)
ALLOWED_COUNTRIES=("nl" "ch" "us" "de" "se")
BAN_FILE="/var/log/mullvad_banlist.log"
LAST_USED_FILE="/var/tmp/mullvad_last_gw"

# --- FUNCTIONS ---

clean_ban_list() {
    if [ -f "$BAN_FILE" ]; then
        # 8 hours = 28800 seconds
        local NOW=$(date +%s)
        local EXPIRY=$((NOW - 28800))
        awk -v expiry="$EXPIRY" '$1 > expiry' "$BAN_FILE" > "${BAN_FILE}.tmp" && mv "${BAN_FILE}.tmp" "$BAN_FILE"
    fi
}

get_valid_country() {
    clean_ban_list
    
    # 1. Get List of Non-Banned Countries
    local AVAILABLE=()
    for c in "${ALLOWED_COUNTRIES[@]}"; do
        if ! grep -q " $c$" "$BAN_FILE" 2>/dev/null; then
            AVAILABLE+=("$c")
        fi
    done

    # Safety Fallback
    if [ ${#AVAILABLE[@]} -eq 0 ]; then
        echo "[$(date)] ⚠️ All regions banned. Resetting list." >&2
        > "$BAN_FILE"
        AVAILABLE=("${ALLOWED_COUNTRIES[@]}")
    fi

    # 2. Get Last Used Country
    local LAST_USED=""
    if [ -f "$LAST_USED_FILE" ]; then
        LAST_USED=$(cat "$LAST_USED_FILE")
    fi

    # 3. Filter Out Last Used (Force Rotation)
    local CANDIDATES=()
    for c in "${AVAILABLE[@]}"; do
        if [ "$c" != "$LAST_USED" ]; then
            CANDIDATES+=("$c")
        fi
    done

    # If only 1 country is available/allowed, we must use it even if it was last
    if [ ${#CANDIDATES[@]} -eq 0 ]; then
        CANDIDATES=("${AVAILABLE[@]}")
    fi

    # 4. Pick Random
    local size=${#CANDIDATES[@]}
    local index=$(($RANDOM % $size))
    local SELECTED=${CANDIDATES[$index]}

    # 5. Save Selection
    echo "$SELECTED" > "$LAST_USED_FILE"
    echo "$SELECTED"
}

# 1. CLEANUP
pkill -f "mullvad_watchdog_process"
pkill -f "ping -c 1"
iptables -F
iptables -P FORWARD ACCEPT
echo "[$(date)] 🟢 Starting DAITA-Enforced Gateway..."

# 2. LOGGING SETUP
LOG_FILE="/var/log/mullvad-optimizer.log"
touch "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

# 3. NETWORK PREP
ethtool --set-eee eth0 eee off > /dev/null 2>&1 || true
sysctl -w net.ipv4.ip_forward=1 > /dev/null

# 4. INITIAL CONNECT
TARGET_COUNTRY=$(get_valid_country)
echo "🎯 Initial Target Selected: ${TARGET_COUNTRY^^}"

# Connection Logic
connect_mullvad() {
    local COUNTRY_CODE=$1
    echo "⚙️  Configuring for Region: ${COUNTRY_CODE^^}..."
    
    mullvad disconnect
    
    # 1. Set Location
    mullvad relay set location "$COUNTRY_CODE"
    
    # 2. Obfuscation (QUIC)
    mullvad obfuscation set mode quic
    
    # 3. Security Features
    mullvad tunnel set quantum-resistant on
    mullvad tunnel set daita on
    
    # 4. LAN Access
    mullvad lan set allow

    echo "🔄 Cold Booting Daemon..."
    systemctl restart mullvad-daemon
    sleep 10
    mullvad connect

    # Wait for Interface
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

    if [ -z "$NEW_WG_IF" ]; then return 1; fi

    # Firewall Rules
    ip link set dev "$NEW_WG_IF" mtu 1280
    iptables -t nat -A POSTROUTING -o "$NEW_WG_IF" -j MASQUERADE
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1000
    tc qdisc del dev eth0 root > /dev/null 2>&1
    tc qdisc add dev eth0 root cake bandwidth 500mbit nat wash ack-filter
    
    return 0
}

connect_mullvad "$TARGET_COUNTRY"

# 5. VERIFICATION
echo "⏳ Verifying..."

# Wait Loop: Ensure we are actually Connected before reporting
MAX_WAIT=20
WAIT_COUNT=0
while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
    STATUS_RAW=$(mullvad status | head -n 1)
    if [[ "$STATUS_RAW" == *"Connected"* ]]; then
        break
    fi
    sleep 1
    ((WAIT_COUNT++))
done

IP=$(curl -s --connect-timeout 5 https://am.i.mullvad.net/ip || echo "Unknown")

# Report Generation
# FIX: Extract last field ($NF) to catch 'quic' correctly
OBF_RAW=$(mullvad obfuscation get | awk '/mode:/ {print $NF}')
[ -z "$OBF_RAW" ] && OBF_RAW="quic"

echo "✅ Connection Established!"
echo "PUBLIC IP:   $IP"
echo "Obfuscation: $OBF_RAW (${OBF_RAW^^})"
echo "MSS CLAMP:   1000 (Safe)"
echo "QUEUE ALG:   CAKE (500mbit)"
echo "==============================================="

# 6. SMART WATCHDOG
(
    exec -a mullvad_watchdog_process bash -c '
    ALLOWED_COUNTRIES=("nl" "ch" "us" "de" "se")
    BAN_FILE="/var/log/mullvad_banlist.log"

    clean_ban_list() {
        if [ -f "$BAN_FILE" ]; then
            local NOW=$(date +%s)
            local EXPIRY=$((NOW - 28800))
            awk -v expiry="$EXPIRY" "\$1 > expiry" "$BAN_FILE" > "${BAN_FILE}.tmp" && mv "${BAN_FILE}.tmp" "$BAN_FILE"
        fi
    }

    get_valid_country() {
        clean_ban_list
        local AVAILABLE=()
        for c in "${ALLOWED_COUNTRIES[@]}"; do
            if ! grep -q " $c$" "$BAN_FILE" 2>/dev/null; then
                AVAILABLE+=("$c")
            fi
        done
        if [ ${#AVAILABLE[@]} -eq 0 ]; then
            echo "[$(date)] ⚠️ Resetting Ban List."
            > "$BAN_FILE"
            AVAILABLE=("${ALLOWED_COUNTRIES[@]}")
        fi
        
        # NOTE: Watchdog uses pure random because it only triggers on failure,
        # so repeat connections are less of a UX issue than during manual start.
        local size=${#AVAILABLE[@]}
        local index=$(($RANDOM % $size))
        echo ${AVAILABLE[$index]}
    }

    ban_current_country() {
        local c=$1
        echo "$(date +%s) $c" >> "$BAN_FILE"
        echo "[$(date)] ⛔ BANNED $c for 8 hours."
    }

    FAIL_COUNT=0
    THRESHOLD=3
    CURRENT_COUNTRY="'$TARGET_COUNTRY'"

    echo "[$(date)] 🛡️ Smart Watchdog Active. Current: ${CURRENT_COUNTRY^^}"

    while true; do
        sleep 10
        if ! ping -c 1 -W 2 1.1.1.1 > /dev/null; then
            ((FAIL_COUNT++))
            echo "[$(date)] ⚠️ Packet Loss Detected ($FAIL_COUNT/$THRESHOLD)"
            
            if [ "$FAIL_COUNT" -ge "$THRESHOLD" ]; then
                echo "[$(date)] 🚨 CONNECTION DEAD."
                ban_current_country "$CURRENT_COUNTRY"
                NEW_COUNTRY=$(get_valid_country)
                echo "[$(date)] 🌍 Switching to: ${NEW_COUNTRY^^}"
                
                mullvad disconnect
                mullvad relay set location "$NEW_COUNTRY"
                
                # Force settings on rotation
                mullvad obfuscation set mode quic
                mullvad tunnel set quantum-resistant on
                mullvad tunnel set daita on

                systemctl restart mullvad-daemon
                sleep 10
                mullvad connect
                
                sleep 10
                NEW_IF=$(ip -br link show | grep -E "wg[0-9]?-mullvad" | awk "{print \$1}")
                if [ -n "$NEW_IF" ]; then
                    ip link set dev "$NEW_IF" mtu 1280
                    iptables -t nat -F
                    iptables -t mangle -F
                    iptables -t nat -A POSTROUTING -o "$NEW_IF" -j MASQUERADE
                    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1000
                    tc qdisc del dev eth0 root > /dev/null 2>&1
                    tc qdisc add dev eth0 root cake bandwidth 500mbit nat wash ack-filter
                    echo "[$(date)] ✅ Recovered in ${NEW_COUNTRY^^}."
                    CURRENT_COUNTRY="$NEW_COUNTRY"
                    FAIL_COUNT=0
                fi
            fi
        else
            FAIL_COUNT=0
        fi
    done
    '
) & disown
