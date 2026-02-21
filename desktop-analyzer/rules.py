"""
Rule Engine for CPE Log Analysis

Implements sliding-window pattern matching for known broadband CPE
failure signatures: PPPoE flaps, DHCP exhaustion, link flapping, etc.
"""

import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger("analyzer.rules")


@dataclass
class SlidingWindow:
    """Counts events in a time-based sliding window."""
    window_sec: int
    events: list = field(default_factory=list)

    def add(self, timestamp: float = None):
        self.events.append(timestamp or time.time())
        self._evict()

    def count(self) -> int:
        self._evict()
        return len(self.events)

    def _evict(self):
        cutoff = time.time() - self.window_sec
        self.events = [t for t in self.events if t > cutoff]


class RuleEngine:
    """
    Evaluates incoming log messages against a set of rules.
    Each rule tracks state via sliding windows and emits alerts
    when thresholds are exceeded.
    """

    def __init__(self):
        # Sliding windows keyed by (cpe_id, rule_name)
        # Each window tracks event count over a time period
        self._windows: dict[tuple[str, str], SlidingWindow] = defaultdict(
            lambda: SlidingWindow(window_sec=600)
        )
        # Cooldown: don't re-fire the same alert within this period
        self._last_alert: dict[tuple[str, str], float] = {}
        self._cooldown_sec = 300  # 5 minutes between repeated alerts

        # Compile regex patterns once
        self._patterns = {
            "pppoe_terminate": re.compile(
                r"(padt|session\s+terminat|pppoe\s+(down|fail|disconnect)|pppd.*exit|lcp\s+down)",
                re.IGNORECASE,
            ),
            "dhcp_nak": re.compile(
                r"(dhcp\s*nak|dhcpnak|nak\s+from|no\s+lease|lease\s+fail|dhcp.*decline)",
                re.IGNORECASE,
            ),
            "link_down": re.compile(
                r"(link\s+down|carrier\s+lost|no\s+carrier|link\s+is\s+down|interface\s+down)",
                re.IGNORECASE,
            ),
            "link_up": re.compile(
                r"(link\s+up|carrier\s+detect|link\s+is\s+up|interface\s+up)",
                re.IGNORECASE,
            ),
            "wifi_deauth": re.compile(
                r"(deauth|disassoc|sta\s+left|station.*left|kicked)",
                re.IGNORECASE,
            ),
            "kernel_error": re.compile(
                r"(segfault|oops|panic|oom[_\s-]kill|out\s+of\s+memory|bug:|rcu\s+stall)",
                re.IGNORECASE,
            ),
            "auth_failure": re.compile(
                r"(auth.*fail|login.*fail|invalid\s+password|access\s+denied|authentication\s+failure)",
                re.IGNORECASE,
            ),
            "dns_failure": re.compile(
                r"(dns.*fail|resolve.*fail|nxdomain|servfail|name.*resolution.*fail)",
                re.IGNORECASE,
            ),
            "crc_fec_error": re.compile(
                r"(crc\s+error|fec\s+error|hec\s+error|line\s+error|dsl.*error|snr\s+drop)",
                re.IGNORECASE,
            ),
        }

        # Rule definitions: pattern_key -> (threshold, window_sec, severity, summary_template)
        self._rules = [
            {
                "name": "pppoe_instability",
                "pattern": "pppoe_terminate",
                "threshold": 3,
                "window_sec": 600,  # 10 min
                "severity": "critical",
                "summary": "PPPoE session terminated {count} times in {window} min — connection instability",
            },
            {
                "name": "dhcp_exhaustion",
                "pattern": "dhcp_nak",
                "threshold": 5,
                "window_sec": 600,
                "severity": "critical",
                "summary": "DHCP NAK received {count} times in {window} min — pool exhaustion or config mismatch",
            },
            {
                "name": "link_flapping",
                "pattern": "link_down",
                "threshold": 3,
                "window_sec": 300,  # 5 min
                "severity": "warning",
                "summary": "Link went down {count} times in {window} min — link flapping detected",
            },
            {
                "name": "wifi_deauth_storm",
                "pattern": "wifi_deauth",
                "threshold": 10,
                "window_sec": 300,
                "severity": "warning",
                "summary": "{count} Wi-Fi deauth events in {window} min — possible interference or attack",
            },
            {
                "name": "kernel_crash",
                "pattern": "kernel_error",
                "threshold": 1,
                "window_sec": 60,
                "severity": "critical",
                "summary": "Kernel error detected: segfault/OOM/panic — system stability at risk",
            },
            {
                "name": "auth_brute_force",
                "pattern": "auth_failure",
                "threshold": 5,
                "window_sec": 300,
                "severity": "warning",
                "summary": "{count} authentication failures in {window} min — possible brute-force attempt",
            },
            {
                "name": "dns_resolution_failure",
                "pattern": "dns_failure",
                "threshold": 5,
                "window_sec": 300,
                "severity": "warning",
                "summary": "DNS resolution failing — {count} failures in {window} min",
            },
            {
                "name": "line_degradation",
                "pattern": "crc_fec_error",
                "threshold": 10,
                "window_sec": 1800,  # 30 min
                "severity": "warning",
                "summary": "{count} CRC/FEC errors in {window} min — DSL line degradation, dropout risk",
            },
        ]

    def evaluate(self, ts: str, cpe_id: str, ident: str, message: str) -> list[dict]:
        """
        Evaluate a single log message against all rules.
        Returns a list of alert dicts (may be empty).
        """
        if not message:
            return []

        alerts = []
        now = time.time()

        for rule in self._rules:
            pattern = self._patterns.get(rule["pattern"])
            if pattern and pattern.search(message):
                # Get or create the sliding window for this CPE + rule
                key = (cpe_id, rule["name"])

                if key not in self._windows or self._windows[key].window_sec != rule["window_sec"]:
                    self._windows[key] = SlidingWindow(window_sec=rule["window_sec"])

                window = self._windows[key]
                window.add(now)
                count = window.count()

                logger.debug(
                    "Rule %s matched on %s: %d/%d in %ds",
                    rule["name"], cpe_id, count, rule["threshold"], rule["window_sec"],
                )

                # Check threshold
                if count >= rule["threshold"]:
                    # Check cooldown
                    last = self._last_alert.get(key, 0)
                    if now - last >= self._cooldown_sec:
                        self._last_alert[key] = now
                        summary = rule["summary"].format(
                            count=count,
                            window=rule["window_sec"] // 60,
                        )
                        alerts.append({
                            "rule": rule["name"],
                            "severity": rule["severity"],
                            "summary": summary,
                            "details": f"Pattern matched in: {message[:200]}",
                        })
                        logger.info("Alert fired: %s on %s", rule["name"], cpe_id)

        return alerts
