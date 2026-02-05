#!/bin/bash

# Logging helper functions for projektarbeit-fap
# These functions expect the following variables to be defined by the
# caller (sourced script): LOG_BLOCKED, LOG_ALLOWED_DOMAINS, LOG_MAIN,
# ALLOWED_DOMAINS, BLOCKED_DOMAINS

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

log_session_summary() {
    echo "" | tee -a "$LOG_MAIN"
    echo "=== SESSION SUMMARY ===" | tee -a "$LOG_MAIN"
    echo "Blocked domains: $(wc -l < \"$LOG_BLOCKED\")" | tee -a "$LOG_MAIN"
    echo "Allowed domains: $(wc -l < \"$LOG_ALLOWED_DOMAINS\")" | tee -a "$LOG_MAIN"
    echo "Allowed IPv4: $(wc -l < \"$LOG_ALLOWED_IPV4\")" | tee -a "$LOG_MAIN"
    echo "Allowed IPv6: $(wc -l < \"$LOG_ALLOWED_IPV6\")" | tee -a "$LOG_MAIN"
    echo "=======================" | tee -a "$LOG_MAIN"
}
