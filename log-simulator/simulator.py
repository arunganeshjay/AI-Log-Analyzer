"""
Log Simulator for AI Log Analyzer

Generates realistic broadband CPE syslog messages and sends them to
the desktop analyzer. Supports different scenarios:
  - normal:   mostly INFO-level, occasional warnings
  - pppoe:    PPPoE session flapping
  - dhcp:     DHCP NAK flood
  - linkflap: Ethernet link up/down cycling
  - storm:    mixed failure scenario (all of the above)
"""

import json
import os
import random
import sys
import time
from datetime import datetime, timezone

import requests

ANALYZER_URL = os.environ.get("ANALYZER_URL", "http://localhost:8080/api/v1/logs")
RATE = float(os.environ.get("RATE", "2"))  # logs per second
SCENARIO = os.environ.get("SCENARIO", "normal")
CPE_ID = os.environ.get("CPE_ID", "cpe-sim-001")

# ---------------------------------------------------------------------------
# Log templates
# ---------------------------------------------------------------------------

NORMAL_LOGS = [
    ("syslog", "info", "System uptime: {uptime} days"),
    ("syslog", "info", "Memory usage: {mem}% ({used}MB / {total}MB)"),
    ("kernel", "info", "eth0: link speed 1000 Mbps full duplex"),
    ("pppd", "info", "PPPoE session established, IP: 100.64.{o3}.{o4}"),
    ("dhclient", "info", "DHCPACK from 192.168.1.1 (xid=0x{xid})"),
    ("dhcpd", "info", "DHCPACK on 192.168.1.{client} to {mac}"),
    ("hostapd", "info", "wlan0: STA {mac} IEEE 802.11: associated"),
    ("hostapd", "info", "wlan0: STA {mac} WPA: pairwise key handshake completed"),
    ("dnsmasq", "info", "query[A] www.example.com from 192.168.1.{client}"),
    ("ntpd", "info", "NTP sync to time.google.com, offset +0.{offset}ms"),
    ("crond", "info", "Job `health-check` completed, status: OK"),
    ("syslog", "info", "CPU temperature: {temp}°C"),
    ("kernel", "info", "DSL line sync rate: down {down}kbps up {up}kbps"),
]

PPPOE_FAILURE_LOGS = [
    ("pppd", "warning", "PPPoE: PADT received from AC"),
    ("pppd", "error", "PPPoE session terminated"),
    ("pppd", "warning", "LCP down"),
    ("pppd", "info", "PPPoE: sending PADI"),
    ("pppd", "info", "PPPoE: received PADO"),
    ("pppd", "info", "PPPoE: sending PADR"),
    ("pppd", "error", "PPPoE: connection failed, retrying..."),
    ("pppd", "error", "PPPoE: session terminated unexpectedly"),
    ("pppd", "warning", "PPPoE: timeout waiting for PADS"),
    ("pppd", "error", "pppd exit code 8 (connect script failed)"),
]

DHCP_FAILURE_LOGS = [
    ("dhclient", "error", "DHCPNAK from 192.168.1.1 (xid=0x{xid})"),
    ("dhclient", "warning", "No lease, failing over to static config"),
    ("dhclient", "error", "DHCP NAK from server, lease declined"),
    ("dhcpd", "warning", "DHCPNAK on 192.168.1.{client} to {mac}"),
    ("dhcpd", "error", "No free leases in pool 192.168.1.0/24"),
    ("dhclient", "error", "DHCP lease failed, no IP assigned"),
]

LINK_FLAP_LOGS = [
    ("kernel", "error", "eth0: link down"),
    ("kernel", "info", "eth0: link up at 100 Mbps full duplex"),
    ("kernel", "error", "eth0: link down"),
    ("kernel", "info", "eth0: link up at 1000 Mbps full duplex"),
    ("kernel", "warning", "eth0: carrier lost"),
    ("kernel", "info", "eth0: carrier detected"),
]

KERNEL_ERROR_LOGS = [
    ("kernel", "error", "BUG: kernel NULL pointer dereference at 0000000000000042"),
    ("kernel", "error", "Out of memory: Kill process 1234 (hostapd) score 950"),
    ("kernel", "error", "segfault at 0 ip 00007f2a3c rsp 00007ffd sp 0 error 4"),
]

WIFI_DEAUTH_LOGS = [
    ("hostapd", "warning", "wlan0: STA {mac} IEEE 802.11: deauthenticated"),
    ("hostapd", "warning", "wlan0: STA {mac} IEEE 802.11: disassociated"),
    ("hostapd", "info", "wlan0: STA {mac} left the BSS"),
]

DSL_ERROR_LOGS = [
    ("kernel", "warning", "DSL: CRC error count increased to {count}"),
    ("kernel", "warning", "DSL: FEC error rate above threshold"),
    ("kernel", "warning", "DSL: SNR drop detected, margin: {snr}dB"),
    ("kernel", "error", "DSL: line error, retraining..."),
]


def random_mac():
    return ":".join(f"{random.randint(0,255):02x}" for _ in range(6))


def fill_template(msg: str) -> str:
    return msg.format(
        uptime=random.randint(1, 365),
        mem=random.randint(30, 90),
        used=random.randint(50, 120),
        total=128,
        o3=random.randint(0, 255),
        o4=random.randint(1, 254),
        xid=f"{random.randint(0, 0xFFFFFFFF):08x}",
        client=random.randint(100, 254),
        mac=random_mac(),
        offset=random.randint(1, 999),
        temp=random.randint(40, 75),
        down=random.randint(10000, 100000),
        up=random.randint(1000, 20000),
        count=random.randint(100, 9999),
        snr=random.randint(3, 12),
    )


def generate_log(scenario: str) -> dict:
    """Generate a single log entry based on the scenario."""
    if scenario == "pppoe":
        pool = NORMAL_LOGS * 2 + PPPOE_FAILURE_LOGS * 5
    elif scenario == "dhcp":
        pool = NORMAL_LOGS * 2 + DHCP_FAILURE_LOGS * 5
    elif scenario == "linkflap":
        pool = NORMAL_LOGS * 2 + LINK_FLAP_LOGS * 5
    elif scenario == "storm":
        pool = (
            NORMAL_LOGS
            + PPPOE_FAILURE_LOGS * 3
            + DHCP_FAILURE_LOGS * 3
            + LINK_FLAP_LOGS * 3
            + WIFI_DEAUTH_LOGS * 2
            + DSL_ERROR_LOGS * 2
        )
    elif scenario == "kernel":
        pool = NORMAL_LOGS * 5 + KERNEL_ERROR_LOGS * 2
    else:  # normal
        pool = NORMAL_LOGS * 10 + [
            ("syslog", "warning", "High CPU usage: {mem}%"),
            ("kernel", "warning", "eth0: received packet with wrong checksum"),
        ]

    ident, severity, template = random.choice(pool)
    message = fill_template(template)
    now = datetime.now(timezone.utc).isoformat()

    return {
        "timestamp": now,
        "cpe_id": CPE_ID,
        "host": CPE_ID,
        "ident": ident,
        "severity": severity,
        "message": message,
    }


def main():
    print(f"Log Simulator started: scenario={SCENARIO}, rate={RATE}/s, target={ANALYZER_URL}")
    batch_size = max(1, int(RATE))
    interval = batch_size / RATE if RATE > 0 else 1.0

    while True:
        batch = [generate_log(SCENARIO) for _ in range(batch_size)]
        try:
            resp = requests.post(ANALYZER_URL, json=batch, timeout=5)
            result = resp.json()
            alerts = result.get("alerts", 0)
            status = f"  ** {alerts} ALERT(S) **" if alerts else ""
            print(f"Sent {len(batch)} logs → {resp.status_code}{status}")
        except requests.exceptions.ConnectionError:
            print(f"Connection error — analyzer at {ANALYZER_URL} unreachable, retrying...")
        except Exception as e:
            print(f"Error: {e}")

        time.sleep(interval)


if __name__ == "__main__":
    main()
