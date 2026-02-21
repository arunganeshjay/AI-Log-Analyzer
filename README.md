# AI Log Analyzer for Broadband CPE

A log analysis system for broadband CPE (Customer Premises Equipment) devices that detects anomalies, diagnoses root causes, and alerts on failure patterns from syslog, DHCP, PPPoE, and other network logs.

**Architecture:** A lightweight Fluent Bit agent on the CPE forwards logs to a Python-based analyzer on your desktop. The analyzer applies a rule engine for known failure signatures, tracks metrics over time, and exposes a real-time web dashboard.

```
┌─────────────────────┐         HTTP/JSON         ┌─────────────────────────────┐
│     CPE Device      │ ──────────────────────────▶│     Desktop Analyzer        │
│                     │                            │                             │
│  ┌───────────────┐  │                            │  ┌───────────┐  ┌────────┐  │
│  │  Fluent Bit   │  │                            │  │Rule Engine│  │SQLite  │  │
│  │  (tail syslog │  │                            │  │(pattern   │  │(logs + │  │
│  │   + forward)  │  │                            │  │ matching) │  │metrics)│  │
│  └───────────────┘  │                            │  └───────────┘  └────────┘  │
│       ~15 MB RAM    │                            │  ┌──────────────────────┐   │
│                     │                            │  │  Web Dashboard :8080 │   │
└─────────────────────┘                            │  └──────────────────────┘   │
                                                   └─────────────────────────────┘
```

## Project Structure

```
AI-Log-Analyzer/
├── cpe-agent/                  # Runs ON the CPE device
│   ├── Dockerfile              # ARM64 Fluent Bit image
│   ├── fluent-bit.conf         # Log collection & forwarding config
│   ├── parsers.conf            # Syslog parsers (RFC 3164, RFC 5424)
│   └── README.md
├── desktop-analyzer/           # Runs on your desktop (Docker)
│   ├── Dockerfile
│   ├── analyzer.py             # Flask service: ingestion, dashboard, API
│   ├── rules.py                # Rule engine: sliding-window pattern detection
│   └── requirements.txt
├── log-simulator/              # Generates fake CPE logs for testing
│   ├── Dockerfile
│   ├── simulator.py            # Configurable log generator (multiple scenarios)
│   └── requirements.txt
├── Plan/
│   └── plan-aiLogAnalyzer.prompt.md
├── docker-compose.yml          # Orchestrates desktop services
├── .gitignore
├── LICENSE
└── README.md
```

## Quick Start

### 1. Run the Desktop Analyzer

```bash
docker compose up --build analyzer
```

The dashboard is at **http://localhost:8080** and the log ingestion API is at `POST http://localhost:8080/api/v1/logs`.

### 2. Test with the Log Simulator

Run the simulator alongside the analyzer to see it in action without a real CPE:

```bash
# Normal traffic (mostly healthy logs)
docker compose --profile testing up --build

# Simulate a PPPoE flapping failure
docker compose --profile testing run -e SCENARIO=pppoe log-simulator

# Simulate DHCP exhaustion
docker compose --profile testing run -e SCENARIO=dhcp log-simulator

# Simulate link flapping
docker compose --profile testing run -e SCENARIO=linkflap log-simulator

# Simulate a mixed failure storm
docker compose --profile testing run -e SCENARIO=storm log-simulator
```

### 3. Deploy the CPE Agent (on a real device)

On the ARM-based CPE:

```bash
cd cpe-agent
docker build -t ai-log-analyzer/cpe-agent:latest .

docker run -d \
  --name cpe-agent \
  --memory=30m \
  -v /var/log/syslog:/var/log/syslog:ro \
  -e CPE_ID=my-router-001 \
  -e CPE_MODEL=MyRouter-3000 \
  -e FIRMWARE_VERSION=2.1.0 \
  -e DESKTOP_HOST=192.168.1.100 \
  -e DESKTOP_PORT=8080 \
  -p 5140:5140/udp \
  ai-log-analyzer/cpe-agent:latest
```

Or send logs directly to the agent's syslog input from the CPE:

```bash
echo "<134>Feb 20 10:00:00 cpe pppd[1234]: PPPoE session terminated" | nc -u -w1 localhost 5140
```

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Web dashboard (auto-refreshes every 15s) |
| `/api/v1/logs` | POST | Ingest logs (JSON array or object) |
| `/api/v1/alerts` | GET | Retrieve recent alerts |
| `/api/v1/stats` | GET | Summary statistics (24h) |
| `/api/v1/health` | GET | Health check |

## Detection Rules

The rule engine uses sliding-window counters to detect known CPE failure patterns:

| Rule | Trigger | Severity |
|---|---|---|
| **PPPoE Instability** | 3+ session terminations in 10 min | Critical |
| **DHCP Exhaustion** | 5+ NAKs in 10 min | Critical |
| **Link Flapping** | 3+ link-down events in 5 min | Warning |
| **Wi-Fi Deauth Storm** | 10+ deauths in 5 min | Warning |
| **Kernel Crash** | Any segfault/OOM/panic | Critical |
| **Auth Brute Force** | 5+ auth failures in 5 min | Warning |
| **DNS Resolution Failure** | 5+ DNS failures in 5 min | Warning |
| **DSL Line Degradation** | 10+ CRC/FEC errors in 30 min | Warning |

Each rule has a 5-minute cooldown to avoid alert flooding.

## Resource Usage

| Component | RAM | Notes |
|---|---|---|
| CPE Agent (Fluent Bit) | ~15 MB | Tails syslog, forwards over HTTP |
| Desktop Analyzer | ~50 MB | Flask + SQLite + rule engine |
| Log Simulator | ~30 MB | Only used for testing |

## Roadmap

- [ ] Add Isolation Forest anomaly detection (ONNX model)
- [ ] Integrate Ollama LLM for natural-language root-cause diagnosis
- [ ] Add Grafana dashboards for richer visualization
- [ ] Implement CPE-side anomaly scoring (hybrid architecture)
- [ ] Add MQTT alert channel for edge notifications
- [ ] Time-series trend prediction for proactive warnings
- [ ] Auto-remediation hooks (desktop → CPE command channel)

## License

See [LICENSE](LICENSE).