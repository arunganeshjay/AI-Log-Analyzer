"""
AI Log Analyzer - Desktop Analyzer Service

Receives logs from CPE agents via HTTP, applies rule-based detection,
tracks metrics, and exposes a simple web dashboard.
"""

import json
import logging
import os
import sqlite3
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, request, render_template_string

from rules import RuleEngine

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DB_PATH = os.environ.get("DB_PATH", "/data/analyzer.db")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
METRICS_WINDOW_SEC = int(os.environ.get("METRICS_WINDOW_SEC", "300"))  # 5 min

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("analyzer")

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
_db_lock = threading.Lock()


def get_db() -> sqlite3.Connection:
    """Return a thread-local SQLite connection."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Create tables if they don't exist."""
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT NOT NULL,
            received  TEXT NOT NULL,
            cpe_id    TEXT,
            host      TEXT,
            ident     TEXT,
            pid       TEXT,
            severity  TEXT,
            facility  TEXT,
            message   TEXT,
            raw       TEXT
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT NOT NULL,
            cpe_id    TEXT,
            rule_name TEXT NOT NULL,
            severity  TEXT NOT NULL,
            summary   TEXT NOT NULL,
            details   TEXT
        );

        CREATE TABLE IF NOT EXISTS metrics (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            bucket    TEXT NOT NULL,
            cpe_id    TEXT,
            category  TEXT NOT NULL,
            count     INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
        CREATE INDEX IF NOT EXISTS idx_metrics_bucket ON metrics(bucket, cpe_id);
        """
    )
    conn.close()
    logger.info("Database initialized at %s", DB_PATH)


# ---------------------------------------------------------------------------
# In-memory metric counters (flushed to DB every METRICS_WINDOW_SEC)
# ---------------------------------------------------------------------------
_counters: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
_counter_lock = threading.Lock()


def _classify_log(message: str) -> str:
    """Classify a log message into a broad category."""
    msg = message.lower() if message else ""
    if any(k in msg for k in ("pppoe", "pppd", "padi", "pado", "padr", "pads", "padt")):
        return "pppoe"
    if any(k in msg for k in ("dhcp", "discover", "offer", "request", "ack", "nak", "dhclient")):
        return "dhcp"
    if any(k in msg for k in ("wlan", "wifi", "802.11", "assoc", "deauth", "disassoc", "hostapd")):
        return "wifi"
    if any(k in msg for k in ("link down", "link up", "carrier", "eth", "dsl")):
        return "link"
    if any(k in msg for k in ("kernel", "oom", "segfault", "panic", "oops")):
        return "kernel"
    if any(k in msg for k in ("error", "err", "crit", "alert", "emerg")):
        return "error"
    return "other"


def increment_counter(cpe_id: str, category: str):
    key = cpe_id or "unknown"
    with _counter_lock:
        _counters[key][category] += 1


def flush_counters():
    """Flush in-memory counters to the metrics table."""
    bucket = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M")
    with _counter_lock:
        snapshot = dict(_counters)
        _counters.clear()

    if not snapshot:
        return

    conn = get_db()
    with _db_lock:
        for cpe_id, cats in snapshot.items():
            for category, count in cats.items():
                conn.execute(
                    "INSERT INTO metrics (bucket, cpe_id, category, count) VALUES (?, ?, ?, ?)",
                    (bucket, cpe_id, category, count),
                )
        conn.commit()
    conn.close()
    logger.debug("Flushed metric counters for bucket %s", bucket)


def _counter_flusher():
    """Background thread that periodically flushes counters."""
    while True:
        time.sleep(METRICS_WINDOW_SEC)
        try:
            flush_counters()
        except Exception:
            logger.exception("Counter flush failed")


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)
rule_engine = RuleEngine()

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>AI Log Analyzer</title>
    <meta http-equiv="refresh" content="15">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f1117; color: #e0e0e0; padding: 20px; }
        h1 { color: #58a6ff; margin-bottom: 20px; }
        h2 { color: #8b949e; margin: 20px 0 10px; font-size: 1.1em; text-transform: uppercase; letter-spacing: 1px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }
        .card .label { color: #8b949e; font-size: 0.85em; }
        .card .value { font-size: 2em; font-weight: bold; color: #58a6ff; margin-top: 5px; }
        .card.alert .value { color: #f85149; }
        .card.warn .value { color: #d29922; }
        .card.ok .value { color: #3fb950; }
        table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }
        th { background: #21262d; color: #8b949e; text-align: left; padding: 10px 15px; font-size: 0.85em; text-transform: uppercase; }
        td { padding: 8px 15px; border-top: 1px solid #30363d; font-size: 0.9em; }
        tr:hover { background: #1c2128; }
        .sev-critical { color: #f85149; font-weight: bold; }
        .sev-warning { color: #d29922; }
        .sev-info { color: #58a6ff; }
        .empty { color: #484f58; text-align: center; padding: 40px; }
    </style>
</head>
<body>
    <h1>&#x1F4CA; AI Log Analyzer Dashboard</h1>

    <h2>Overview</h2>
    <div class="grid">
        <div class="card"><div class="label">Total Logs (24h)</div><div class="value">{{ stats.total_logs }}</div></div>
        <div class="card {{ 'alert' if stats.active_alerts > 0 else 'ok' }}"><div class="label">Active Alerts</div><div class="value">{{ stats.active_alerts }}</div></div>
        <div class="card"><div class="label">CPE Devices</div><div class="value">{{ stats.cpe_count }}</div></div>
        <div class="card {{ 'warn' if stats.error_rate > 10 else 'ok' }}"><div class="label">Error Rate (5m)</div><div class="value">{{ "%.1f"|format(stats.error_rate) }}%</div></div>
    </div>

    <h2>Recent Alerts</h2>
    {% if alerts %}
    <table>
        <thead><tr><th>Time</th><th>CPE</th><th>Rule</th><th>Severity</th><th>Summary</th></tr></thead>
        <tbody>
        {% for a in alerts %}
        <tr>
            <td>{{ a.ts }}</td>
            <td>{{ a.cpe_id }}</td>
            <td>{{ a.rule_name }}</td>
            <td class="sev-{{ a.severity }}">{{ a.severity }}</td>
            <td>{{ a.summary }}</td>
        </tr>
        {% endfor %}
        </tbody>
    </table>
    {% else %}
    <div class="empty">No alerts — system healthy</div>
    {% endif %}

    <h2>Recent Logs</h2>
    {% if logs %}
    <table>
        <thead><tr><th>Time</th><th>CPE</th><th>Source</th><th>Message</th></tr></thead>
        <tbody>
        {% for l in logs %}
        <tr>
            <td>{{ l.ts }}</td>
            <td>{{ l.cpe_id }}</td>
            <td>{{ l.ident }}</td>
            <td>{{ l.message }}</td>
        </tr>
        {% endfor %}
        </tbody>
    </table>
    {% else %}
    <div class="empty">No logs received yet</div>
    {% endif %}
</body>
</html>
"""


@app.route("/")
def dashboard():
    conn = get_db()
    now = datetime.now(timezone.utc)
    day_ago = (now - timedelta(hours=24)).isoformat()
    five_min_ago = (now - timedelta(minutes=5)).isoformat()

    total_logs = conn.execute(
        "SELECT COUNT(*) FROM logs WHERE ts >= ?", (day_ago,)
    ).fetchone()[0]

    active_alerts = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE ts >= ?", (day_ago,)
    ).fetchone()[0]

    cpe_count = conn.execute(
        "SELECT COUNT(DISTINCT cpe_id) FROM logs WHERE ts >= ?", (day_ago,)
    ).fetchone()[0]

    # Error rate = error logs / total logs in last 5 min
    recent_total = conn.execute(
        "SELECT COUNT(*) FROM logs WHERE ts >= ?", (five_min_ago,)
    ).fetchone()[0]
    recent_errors = conn.execute(
        "SELECT COUNT(*) FROM logs WHERE ts >= ? AND ("
        "message LIKE '%error%' OR message LIKE '%crit%' OR "
        "message LIKE '%alert%' OR message LIKE '%emerg%')",
        (five_min_ago,),
    ).fetchone()[0]
    error_rate = (recent_errors / recent_total * 100) if recent_total > 0 else 0.0

    alerts = conn.execute(
        "SELECT ts, cpe_id, rule_name, severity, summary FROM alerts ORDER BY ts DESC LIMIT 20"
    ).fetchall()

    logs = conn.execute(
        "SELECT ts, cpe_id, ident, message FROM logs ORDER BY ts DESC LIMIT 50"
    ).fetchall()

    conn.close()

    stats = {
        "total_logs": total_logs,
        "active_alerts": active_alerts,
        "cpe_count": cpe_count,
        "error_rate": error_rate,
    }
    return render_template_string(
        DASHBOARD_HTML,
        stats=stats,
        alerts=[dict(a) for a in alerts],
        logs=[dict(l) for l in logs],
    )


@app.route("/api/v1/logs", methods=["POST"])
def ingest_logs():
    """Receive logs from Fluent Bit (JSON array or single object)."""
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"error": "invalid JSON"}), 400

    # Fluent Bit sends an array of records
    records = data if isinstance(data, list) else [data]
    now = datetime.now(timezone.utc).isoformat()

    conn = get_db()
    alerts_generated = []

    with _db_lock:
        for record in records:
            ts = record.get("timestamp") or record.get("date") or record.get("time") or now
            cpe_id = record.get("cpe_id", "unknown")
            host = record.get("host", "")
            ident = record.get("ident", "")
            pid = record.get("pid", "")
            message = record.get("message", "")

            # Store log
            conn.execute(
                "INSERT INTO logs (ts, received, cpe_id, host, ident, pid, message, raw) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (ts, now, cpe_id, host, ident, pid, message, json.dumps(record)),
            )

            # Classify & count
            category = _classify_log(message)
            increment_counter(cpe_id, category)

            # Run rule engine
            new_alerts = rule_engine.evaluate(
                ts=ts, cpe_id=cpe_id, ident=ident, message=message
            )
            for alert in new_alerts:
                conn.execute(
                    "INSERT INTO alerts (ts, cpe_id, rule_name, severity, summary, details) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (ts, cpe_id, alert["rule"], alert["severity"], alert["summary"], alert.get("details", "")),
                )
                alerts_generated.append(alert)
                logger.warning(
                    "ALERT [%s] %s on %s: %s",
                    alert["severity"],
                    alert["rule"],
                    cpe_id,
                    alert["summary"],
                )

        conn.commit()
    conn.close()

    return jsonify({
        "status": "ok",
        "ingested": len(records),
        "alerts": len(alerts_generated),
    })


@app.route("/api/v1/alerts", methods=["GET"])
def get_alerts():
    """Return recent alerts as JSON."""
    limit = request.args.get("limit", 50, type=int)
    conn = get_db()
    rows = conn.execute(
        "SELECT ts, cpe_id, rule_name, severity, summary, details FROM alerts ORDER BY ts DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/v1/stats", methods=["GET"])
def get_stats():
    """Return summary statistics."""
    conn = get_db()
    now = datetime.now(timezone.utc)
    day_ago = (now - timedelta(hours=24)).isoformat()

    total = conn.execute("SELECT COUNT(*) FROM logs WHERE ts >= ?", (day_ago,)).fetchone()[0]
    by_category = conn.execute(
        "SELECT category, SUM(count) as total FROM metrics WHERE bucket >= ? GROUP BY category ORDER BY total DESC",
        (day_ago[:16],),
    ).fetchall()
    conn.close()

    return jsonify({
        "total_logs_24h": total,
        "categories": {r["category"]: r["total"] for r in by_category},
    })


@app.route("/api/v1/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "ai-log-analyzer"})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    init_db()

    # Start background counter flusher
    t = threading.Thread(target=_counter_flusher, daemon=True)
    t.start()

    port = int(os.environ.get("PORT", "8080"))
    logger.info("Analyzer listening on port %d", port)
    app.run(host="0.0.0.0", port=port, debug=False)


if __name__ == "__main__":
    main()
