#!/bin/bash

TEMPLATE_FILE="./template.txt"
INTERFACE="wlan0"

SESSION_DIR="./sessions/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$SESSION_DIR"

LOG_BLOCKED="$SESSION_DIR/blocked_domains.log"
LOG_ALLOWED_DOMAINS="$SESSION_DIR/allowed_domains.log"
LOG_ALLOWED_IPV4="$SESSION_DIR/allowed_ipv4.log"
LOG_ALLOWED_IPV6="$SESSION_DIR/allowed_ipv6.log"
LOG_MAIN="$SESSION_DIR/session.log"

touch "$LOG_BLOCKED" "$LOG_ALLOWED_DOMAINS" "$LOG_ALLOWED_IPV4" "$LOG_ALLOWED_IPV6" "$LOG_MAIN"

echo "[SESSION] Started at $(date)" | tee -a "$LOG_MAIN"
echo "[SESSION] Logs directory: $SESSION_DIR" | tee -a "$LOG_MAIN"

declare -A ALLOWED_IPS
declare -A ALLOWED_DOMAINS
declare -A BLOCKED_DOMAINS
declare -A WHITELIST

load_whitelist() {
    echo "[DNS-MONITOR] Loading whitelist from $TEMPLATE_FILE..." | tee -a "$LOG_MAIN"
    while read -r domain || [[ -n "$domain" ]]; do
        domain=$(echo "$domain" | xargs | tr '[:upper:]' '[:lower:]')
        if [[ -n "$domain" ]]; then
            WHITELIST["$domain"]=1
            echo "[DNS-MONITOR] Added to whitelist: $domain" | tee -a "$LOG_MAIN"
        fi
    done < "$TEMPLATE_FILE"
    echo "[DNS-MONITOR] Whitelist loaded: ${!WHITELIST[@]}" | tee -a "$LOG_MAIN"
}

is_whitelisted() {
    local domain="$1"
    domain=$(echo "$domain" | tr '[:upper:]' '[:lower:]' | sed 's/\.$//')
    for allowed in "${!WHITELIST[@]}"; do
        if [[ "$domain" == "$allowed" || "$domain" == *".$allowed" ]]; then
            return 0
        fi
    done
    return 1
}

log_blocked() {
    local domain="$1"
    if [[ -z "${BLOCKED_DOMAINS[$domain]}" ]]; then
        BLOCKED_DOMAINS["$domain"]=1
        echo "$(date +%H:%M:%S) $domain" >> "$LOG_BLOCKED"
        echo "[BLOCKED] $domain" | tee -a "$LOG_MAIN"
    fi
}

log_allowed_domain() {
    local domain="$1"
    if [[ -z "${ALLOWED_DOMAINS[$domain]}" ]]; then
        ALLOWED_DOMAINS["$domain"]=1
        echo "$(date +%H:%M:%S) $domain" >> "$LOG_ALLOWED_DOMAINS"
        echo "[ALLOWED] $domain" | tee -a "$LOG_MAIN"
    fi
}

add_iptables_rule() {
    local ip="$1"
    local domain="$2"
    if [[ -z "${ALLOWED_IPS[$ip]}" ]]; then
        ALLOWED_IPS["$ip"]=1
        if [[ "$ip" == *":"* ]]; then
            sudo ip6tables -A FORWARD -i wlan0 -o eth0 -d "$ip" -j ACCEPT
            sudo ip6tables -A FORWARD -i eth0 -o wlan0 -s "$ip" -m state --state ESTABLISHED,RELATED -j ACCEPT
            echo "$(date +%H:%M:%S) $ip ($domain)" >> "$LOG_ALLOWED_IPV6"
            echo "[IP6TABLES] Allowed $ip ($domain)" | tee -a "$LOG_MAIN"
        else
            sudo iptables -A FORWARD -i wlan0 -o eth0 -d "$ip" -j ACCEPT
            sudo iptables -A FORWARD -i eth0 -o wlan0 -s "$ip" -m state --state ESTABLISHED,RELATED -j ACCEPT
            echo "$(date +%H:%M:%S) $ip ($domain)" >> "$LOG_ALLOWED_IPV4"
            echo "[IPTABLES] Allowed $ip ($domain)" | tee -a "$LOG_MAIN"
        fi
    fi
}

dns_monitor() {
    load_whitelist
    echo "[DNS-MONITOR] Starting tshark on $INTERFACE..." | tee -a "$LOG_MAIN"
    echo "[DNS-MONITOR] Waiting for DNS responses..." | tee -a "$LOG_MAIN"
    
    sudo stdbuf -oL tshark -i "$INTERFACE" -l -Y "dns.a or dns.aaaa" -T fields -e dns.qry.name -e dns.a -e dns.aaaa 2>&1 | while read -r line; do
        if [[ "$line" == *"Capturing on"* ]] || [[ "$line" == *"Running as"* ]]; then
            continue
        fi
        
        domain=$(echo "$line" | awk -F'\t' '{print $1}')
        ipv4=$(echo "$line" | awk -F'\t' '{print $2}')
        ipv6=$(echo "$line" | awk -F'\t' '{print $3}')
        
        if [[ -n "$domain" ]]; then
            domain=$(echo "$domain" | sed 's/\.$//' | tr '[:upper:]' '[:lower:]')
            
            if is_whitelisted "$domain"; then
                log_allowed_domain "$domain"
                
                for ip in $(echo "$ipv4" | tr ',' '\n'); do
                    [[ -z "$ip" ]] && continue
                    add_iptables_rule "$ip" "$domain"
                done
                
                for ip in $(echo "$ipv6" | tr ',' '\n'); do
                    [[ -z "$ip" ]] && continue
                    add_iptables_rule "$ip" "$domain"
                done
            else
                log_blocked "$domain"
            fi
        fi
    done
    
    echo "[DNS-MONITOR] tshark exited" | tee -a "$LOG_MAIN"
}

reset_iptables() {
    echo "[CLEANUP] Resetting iptables rules..." | tee -a "$LOG_MAIN"
    
    sudo iptables -F
    sudo iptables -X
    sudo iptables -t nat -F
    sudo iptables -t nat -X
    sudo iptables -t mangle -F
    sudo iptables -t mangle -X
    sudo iptables -P INPUT ACCEPT
    sudo iptables -P OUTPUT ACCEPT
    sudo iptables -P FORWARD ACCEPT
    
    sudo ip6tables -F
    sudo ip6tables -X
    sudo ip6tables -t nat -F
    sudo ip6tables -t nat -X
    sudo ip6tables -t mangle -F
    sudo ip6tables -t mangle -X
    sudo ip6tables -P INPUT ACCEPT
    sudo ip6tables -P OUTPUT ACCEPT
    sudo ip6tables -P FORWARD ACCEPT
    
    echo "[CLEANUP] iptables reset to default ACCEPT" | tee -a "$LOG_MAIN"
}

# --- CHECKS ---
sudo lsof -i :53
nmcli radio
rfkill list

# --- STOP SERVICES ---
sudo systemctl stop dnsmasq
sudo killall dnsmasq 2>/dev/null
sudo systemctl stop unbound

# --- SETUP INTERFACE ---
sudo nmcli radio wifi on
sudo ip link set wlan0 down
sudo ip addr flush dev wlan0
sudo ip link set wlan0 up
sudo ip addr add 10.10.0.1/24 dev wlan0

# --- IPTABLES FIREWALL SETUP ---
echo "[DEBUG] Flushing existing iptables rules..." | tee -a "$LOG_MAIN"
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X

sudo ip6tables -F
sudo ip6tables -X
sudo ip6tables -t nat -F
sudo ip6tables -t nat -X
sudo ip6tables -t mangle -F
sudo ip6tables -t mangle -X

sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD DROP

sudo ip6tables -P INPUT ACCEPT
sudo ip6tables -P OUTPUT ACCEPT
sudo ip6tables -P FORWARD DROP

echo "[DEBUG] Default policy: INPUT/OUTPUT ACCEPT, FORWARD DROP" | tee -a "$LOG_MAIN"

sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
echo 1 | sudo tee /proc/sys/net/ipv6/conf/all/forwarding

echo "[DEBUG] IPTABLES firewall setup complete." | tee -a "$LOG_MAIN"

# --- START SERVICES ---
sudo dnsmasq --conf-file=dnsmasq.conf

sudo hostapd hostapd-test.conf &
HOSTAPD_PID=$!
sleep 2

echo "[DEBUG] Starting DNS monitor..." | tee -a "$LOG_MAIN"
dns_monitor &
DNS_MONITOR_PID=$!
echo "[DEBUG] DNS monitor PID: $DNS_MONITOR_PID" | tee -a "$LOG_MAIN"

sleep 1
echo "[DEBUG] Starting pcap capture..." | tee -a "$LOG_MAIN"
sudo tshark -i wlan0 -w /tmp/capture.pcap &
TSHARK_PID=$!

# --- CLEANUP ---
cleanup() {
    echo "" | tee -a "$LOG_MAIN"
    echo "[SESSION] Stopping at $(date)" | tee -a "$LOG_MAIN"
    
    sudo kill $HOSTAPD_PID 2>/dev/null
    sudo kill $TSHARK_PID 2>/dev/null
    sudo kill $DNS_MONITOR_PID 2>/dev/null
    sudo pkill -f "tshark -i $INTERFACE -l -Y" 2>/dev/null
    
    wait $HOSTAPD_PID 2>/dev/null
    wait $TSHARK_PID 2>/dev/null
    wait $DNS_MONITOR_PID 2>/dev/null
    
    sudo chmod 644 /tmp/capture.pcap 2>/dev/null
    if [ -f /tmp/capture.pcap ]; then
        cp /tmp/capture.pcap "$SESSION_DIR/capture.pcap"
        echo "[SESSION] capture.pcap copied to session folder" | tee -a "$LOG_MAIN"
    fi
    
    echo "" | tee -a "$LOG_MAIN"
    echo "=== SESSION SUMMARY ===" | tee -a "$LOG_MAIN"
    echo "Blocked domains: $(wc -l < "$LOG_BLOCKED")" | tee -a "$LOG_MAIN"
    echo "Allowed domains: $(wc -l < "$LOG_ALLOWED_DOMAINS")" | tee -a "$LOG_MAIN"
    echo "Allowed IPv4: $(wc -l < "$LOG_ALLOWED_IPV4")" | tee -a "$LOG_MAIN"
    echo "Allowed IPv6: $(wc -l < "$LOG_ALLOWED_IPV6")" | tee -a "$LOG_MAIN"
    echo "=======================" | tee -a "$LOG_MAIN"
    
    reset_iptables
    
    echo "[SESSION] Logs saved to: $SESSION_DIR" | tee -a "$LOG_MAIN"
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

wait $HOSTAPD_PID $TSHARK_PID $DNS_MONITOR_PID