#!/bin/bash

# DNS monitor helpers for projektarbeit-fap
# Expects variables from caller: TEMPLATE_FILE, INTERFACE, LOG_MAIN,
# ALLOWED_IPS, WHITELIST, ALLOWED_DOMAINS, BLOCKED_DOMAINS

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
