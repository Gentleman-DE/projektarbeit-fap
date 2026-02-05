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

# Load logging helper functions
source "./scripts/logging.sh"
source "./scripts/iptables.sh"
source "./scripts/dns_monitor.sh"

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
# DNS monitor provided by ./scripts/dns_monitor.sh

# reset_iptables is provided by ./scripts/iptables.sh

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
setup_iptables

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
    
    log_session_summary
    
    reset_iptables
    
    echo "[SESSION] Logs saved to: $SESSION_DIR" | tee -a "$LOG_MAIN"
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

wait $HOSTAPD_PID $TSHARK_PID $DNS_MONITOR_PID