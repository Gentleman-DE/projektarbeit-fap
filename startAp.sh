#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TEMPLATE_FILE="$SCRIPT_DIR/template.txt"
INTERFACE="wlan0"

SESSION_DIR="$SCRIPT_DIR/sessions/$(date +%Y%m%d_%H%M%S)"
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

# Load helper scripts
source "$SCRIPT_DIR/scripts/logging.sh"
source "$SCRIPT_DIR/scripts/iptables.sh"
source "$SCRIPT_DIR/scripts/dns_monitor.sh"

# Background PID tracking
declare -a BG_PIDS=()
push_pid() { BG_PIDS+=("$1"); }

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
push_pid "$HOSTAPD_PID"
sleep 2

echo "[DEBUG] Starting DNS monitor..." | tee -a "$LOG_MAIN"
dns_monitor &
DNS_MONITOR_PID=$!
push_pid "$DNS_MONITOR_PID"
echo "[DEBUG] DNS monitor PID: $DNS_MONITOR_PID" | tee -a "$LOG_MAIN"

sleep 1
echo "[DEBUG] Starting pcap capture..." | tee -a "$LOG_MAIN"
sudo tshark -i wlan0 -w /tmp/capture.pcap &
TSHARK_PID=$!
push_pid "$TSHARK_PID"

cleanup() {
    # Prevent cleanup from running multiple times
    if [[ -n "${CLEANUP_RUNNING-}" ]]; then
        return
    fi
    CLEANUP_RUNNING=1

    # Disable further traps while cleaning up
    trap - SIGINT SIGTERM EXIT

    echo "" | tee -a "$LOG_MAIN"
    echo "[SESSION] Stopping at $(date)" | tee -a "$LOG_MAIN"

    # Kill tracked background PIDs
    for pid in "${BG_PIDS[@]:-}"; do
        sudo kill "$pid" 2>/dev/null || true
    done
    # Extra safety: kill any remaining tshark processes for the interface
    sudo pkill -f "tshark -i $INTERFACE -l -Y" 2>/dev/null || true

    # Wait for all tracked background PIDs
    for pid in "${BG_PIDS[@]:-}"; do
        wait "$pid" 2>/dev/null || true
    done

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