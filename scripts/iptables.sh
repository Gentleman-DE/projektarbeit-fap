#!/bin/bash

# IPTables helper for projektarbeit-fap
# Expects `LOG_MAIN` to be defined by the caller

setup_iptables() {
    # Reset rules first (shared logic)
    reset_iptables

    # Set default FORWARD policy to DROP for the running session
    sudo iptables -P FORWARD DROP
    sudo ip6tables -P FORWARD DROP
    echo "[DEBUG] Default policy: INPUT/OUTPUT ACCEPT, FORWARD DROP" | tee -a "$LOG_MAIN"

    # Enable NAT/forwarding to external interface
    sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    sudo ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

    echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
    echo 1 | sudo tee /proc/sys/net/ipv6/conf/all/forwarding

    echo "[DEBUG] IPTABLES firewall setup complete." | tee -a "$LOG_MAIN"
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

