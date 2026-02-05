#!/usr/bin/env python3
"""
Template builder TUI
- Starts tshark capturing DNS query names and logs domains to a session file
- Initial screen: live capture view (counts). Press 's' to stop capture and open domain selection TUI.
- Selection TUI: navigate with arrows or 'j'/'k'. Press 'a' to toggle adding a domain to template; when adding, selection moves down one. Press 'q' to save template and exit.
- Saves session in sessions/<timestamp>-<name>/domains.log and template.txt

Requires: Python 3, tshark, sudo for running tshark.
"""

import os
import sys
import time
import threading
import subprocess
import curses
from datetime import datetime
from collections import OrderedDict

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
SESSIONS_DIR = os.path.join(PROJECT_ROOT, 'sessions')
if not os.path.isdir(SESSIONS_DIR):
    os.makedirs(SESSIONS_DIR, exist_ok=True)

INTERFACE = os.environ.get('INTERFACE', 'wlan0')
TSHARK_CMD = ['sudo', 'stdbuf', '-oL', 'tshark', '-i', INTERFACE,
             '-l', '-Y', 'dns.qry.name', '-T', 'fields', '-e', 'dns.qry.name']


def get_base_domain(domain: str) -> str:
    """Return a simple base domain (last two labels) from a fqdn-like name.

    Note: this is a heuristic and does not use the public suffix list.
    """
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain


def build_display_list(raw_domains):
    seen = set()
    out = []
    for d in raw_domains:
        if '.' not in d:
            continue
        base = get_base_domain(d)
        if base not in seen:
            seen.add(base)
            out.append(base)
    return out

class CaptureThread(threading.Thread):
    def __init__(self, cmd, out_file):
        super().__init__(daemon=True)
        self.cmd = cmd
        self.out_file = out_file
        self.process = None
        self._running = threading.Event()
        self._running.set()
        self.domains = []
        self.domains_set = set()

    def run(self):
        with open(self.out_file, 'a') as f:
            self.process = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            while self._running.is_set():
                line = self.process.stdout.readline()
                if not line:
                    if self.process.poll() is not None:
                        break
                    time.sleep(0.01)
                    continue
                domain = line.strip().rstrip('.')
                if domain:
                    # normalize
                    domain = domain.lower()
                    f.write(domain + '\n')
                    f.flush()
                    if domain not in self.domains_set:
                        self.domains_set.add(domain)
                        self.domains.append(domain)
            # ensure process terminated
            if self.process and self.process.poll() is None:
                try:
                    self.process.terminate()
                except Exception:
                    pass
                self.process.wait(timeout=2)

    def stop(self):
        self._running.clear()
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
            except Exception:
                pass


def ensure_accept_all():
    # Set iptables policies to accept traffic (requires sudo)
    cmds = [
        ['sudo', 'iptables', '-F'],
        ['sudo', 'iptables', '-P', 'INPUT', 'ACCEPT'],
        ['sudo', 'iptables', '-P', 'OUTPUT', 'ACCEPT'],
        ['sudo', 'iptables', '-P', 'FORWARD', 'ACCEPT'],
        ['sudo', 'ip6tables', '-F'],
        ['sudo', 'ip6tables', '-P', 'INPUT', 'ACCEPT'],
        ['sudo', 'ip6tables', '-P', 'OUTPUT', 'ACCEPT'],
        ['sudo', 'ip6tables', '-P', 'FORWARD', 'ACCEPT'],
    ]
    for c in cmds:
        try:
            subprocess.run(c, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass


def curses_main(stdscr, capture_thread, session_dir, domain_log_path, template_path):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(200)

    mode = 'capture'  # or 'select'
    selected_idx = 0
    added = OrderedDict()

    while True:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        if mode == 'capture':
            display_list = build_display_list(capture_thread.domains)
            stdscr.addstr(0, 0, f"Capturing DNS on {INTERFACE} — domains: {len(display_list)}")
            stdscr.addstr(1, 0, "Press 's' to stop capture and open domain selector — Press Ctrl-C to abort")
            # show last few base domains
            start = max(0, len(display_list) - (height - 4))
            for i, d in enumerate(display_list[start:], start=start):
                if i - start + 3 >= height:
                    break
                stdscr.addstr(i - start + 3, 2, d)
            try:
                c = stdscr.getch()
            except KeyboardInterrupt:
                c = ord('s')
            if c == ord('s'):
                # stop capture and go to select mode
                capture_thread.stop()
                capture_thread.join(timeout=2)
                mode = 'select'
                selected_idx = 0
                continue
            elif c == ord('q'):
                # abort
                capture_thread.stop()
                capture_thread.join(timeout=2)
                return False
        elif mode == 'select':
            stdscr.addstr(0, 0, "Template builder — navigate with arrows or j/k. 'a' to toggle add/remove. 'w' save & exit, 'q' exit without saving")
            display_list = build_display_list(capture_thread.domains)
            if not display_list:
                stdscr.addstr(2, 0, "No FQDNs captured.")
            else:
                # clamp selected_idx
                if selected_idx < 0:
                    selected_idx = 0
                if selected_idx >= len(display_list):
                    selected_idx = len(display_list) - 1
                # visible window
                win_h = height - 4
                win_start = max(0, selected_idx - win_h//2)
                for idx in range(win_start, min(len(display_list), win_start + win_h)):
                    y = idx - win_start + 2
                    prefix = '> ' if idx == selected_idx else '  '
                    mark = '[X] ' if display_list[idx] in added else '[ ] '
                    line = prefix + mark + display_list[idx]
                    try:
                        stdscr.addnstr(y, 0, line, width - 1)
                    except curses.error:
                        pass
                # key handling
                c = stdscr.getch()
                if c in (curses.KEY_DOWN, ord('j')):
                    selected_idx = min(selected_idx + 1, len(display_list) - 1)
                elif c in (curses.KEY_UP, ord('k')):
                    selected_idx = max(selected_idx - 1, 0)
                elif c == ord('a'):
                    d = display_list[selected_idx]
                    if d in added:
                        # remove
                        del added[d]
                    else:
                        added[d] = True
                        # move down one
                        if selected_idx + 1 < len(display_list):
                            selected_idx += 1
                elif c == ord('w'):
                    # save template and exit
                    with open(template_path, 'w') as tf:
                        for d in added.keys():
                            tf.write(d + '\n')
                    return True
                elif c == ord('q'):
                    return False
                elif c == -1:
                    pass
        stdscr.refresh()


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else ''
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    sess_name = f"{timestamp}-{name}" if name else timestamp
    session_dir = os.path.join(SESSIONS_DIR, sess_name)
    os.makedirs(session_dir, exist_ok=True)

    domain_log = os.path.join(session_dir, 'domains.log')
    template_file = os.path.join(session_dir, 'template.txt')
    session_log = os.path.join(session_dir, 'session.log')

    # prepare environment for helper scripts so they can write into session logs
    env = os.environ.copy()
    env['SESSION_DIR'] = session_dir
    env['LOG_MAIN'] = session_log
    env['LOG_BLOCKED'] = os.path.join(session_dir, 'blocked_domains.log')
    env['LOG_ALLOWED_DOMAINS'] = os.path.join(session_dir, 'allowed_domains.log')
    env['LOG_ALLOWED_IPV4'] = os.path.join(session_dir, 'allowed_ipv4.log')
    env['LOG_ALLOWED_IPV6'] = os.path.join(session_dir, 'allowed_ipv6.log')

    # ensure traffic allowed
    ensure_accept_all()

    # Start AP services (similar to startAp.sh)
    try:
        subprocess.run(['sudo', 'systemctl', 'stop', 'dnsmasq'], check=False)
        subprocess.run(['sudo', 'killall', 'dnsmasq'], check=False)
        subprocess.run(['sudo', 'systemctl', 'stop', 'unbound'], check=False)
    except Exception:
        pass

    # Configure interface
    try:
        subprocess.run(['sudo', 'nmcli', 'radio', 'wifi', 'on'], check=False)
        subprocess.run(['sudo', 'ip', 'link', 'set', INTERFACE, 'down'], check=False)
        subprocess.run(['sudo', 'ip', 'addr', 'flush', 'dev', INTERFACE], check=False)
        subprocess.run(['sudo', 'ip', 'link', 'set', INTERFACE, 'up'], check=False)
        subprocess.run(['sudo', 'ip', 'addr', 'add', '10.10.0.1/24', 'dev', INTERFACE], check=False)
    except Exception:
        pass

    # Ensure iptables are reset to ACCEPT (do not block traffic)
    try:
        ipt_script = os.path.join(SCRIPT_DIR, 'iptables.sh')
        # reset rules, then enable NAT/forwarding so clients get internet access
        cmd = (
            f'source "{ipt_script}"; '
            'reset_iptables; '
            'sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; '
            'echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward >/dev/null '
        )
        subprocess.run(['bash', '-c', cmd], check=False, env=env)
    except Exception:
        pass

    # start dnsmasq and hostapd, redirect their output into the session log
    dnsmasq_proc = None
    hostapd_proc = None
    slog = open(session_log, 'a')
    try:
        dnsmasq_conf = os.path.join(PROJECT_ROOT, 'dnsmasq.conf')
        dnsmasq_proc = subprocess.Popen(['sudo', 'dnsmasq', f'--conf-file={dnsmasq_conf}'], stdout=slog, stderr=slog, env=env)
    except Exception:
        dnsmasq_proc = None

    try:
        hostapd_conf = os.path.join(PROJECT_ROOT, 'hostapd-test.conf')
        hostapd_proc = subprocess.Popen(['sudo', 'hostapd', hostapd_conf], stdout=slog, stderr=slog, env=env)
    except Exception:
        hostapd_proc = None

    # start capture
    cap = CaptureThread(TSHARK_CMD, domain_log)
    cap.start()

    # run curses UI
    try:
        res = curses.wrapper(curses_main, cap, session_dir, domain_log, template_file)
    except Exception as e:
        # on exception, stop capture
        cap.stop()
        cap.join(timeout=2)
        print("Error:", e)
        sys.exit(1)

    # stop capture thread
    cap.stop()
    cap.join(timeout=2)

    # stop AP services and reset iptables
    try:
        if hostapd_proc and hostapd_proc.poll() is None:
            hostapd_proc.terminate()
            hostapd_proc.wait(timeout=2)
    except Exception:
        pass
    try:
        if dnsmasq_proc and dnsmasq_proc.poll() is None:
            dnsmasq_proc.terminate()
            dnsmasq_proc.wait(timeout=2)
    except Exception:
        pass
    try:
        ipt_script = os.path.join(SCRIPT_DIR, 'iptables.sh')
        subprocess.run(['bash', '-c', f'source "{ipt_script}"; reset_iptables'], check=False, env=env)
    except Exception:
        pass

    # close session log file handle used for subprocess output
    try:
        slog.close()
    except Exception:
        pass

    # write session_log summary
    with open(session_log, 'a') as sf:
        sf.write(f"Session saved: {session_dir}\n")

    if res:
        print(f"Template saved to {template_file}")
    else:
        print("No template saved")

if __name__ == '__main__':
    main()
