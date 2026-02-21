## Plan: AI Log Analyzer for Broadband CPE

**TL;DR** — Build a log analysis system for an ARM-based broadband CPE that detects anomalies, diagnoses root causes, and predicts failures from syslog/DHCP/PPPoE logs. Three architecture tiers are explored: (A) CPE-only with lightweight ML, (B) cloud/desktop-only where the CPE just ships logs, and (C) a hybrid where a tiny agent on CPE does real-time filtering and a desktop server runs heavier AI models. Since you have no cloud accounts, the "cloud" component runs on your local desktop via Docker Compose. Alerting-only for now; remediation hooks designed for later.

---

### Option A: CPE-Only (Lightweight On-Device)

**What fits in ~150 MB RAM on ARM:**

1. **Log collector & parser** — A single Go or Rust binary (~10 MB RSS) that tails syslog, parses structured fields (timestamp, facility, severity, message), and feeds a local pipeline. Good candidates:
   - **Vector** (by Datadog, Rust-based) — ARM Docker image exists, ~30 MB RSS baseline. Handles parsing, filtering, and routing.
   - **Fluent Bit** — purpose-built for constrained environments, ~5–15 MB RSS. Has ARM images.

2. **Anomaly detection model** — A small scikit-learn or ONNX model loaded by a Python/Go sidecar:
   - **Isolation Forest** or **One-Class SVM** trained on "normal" log patterns (event rate, error ratio per 5-min window). Model file ~1–5 MB, inference process ~20–40 MB RSS.
   - **ONNX Runtime** has an ARM build; inference is fast and memory-efficient.
   - Alternative: **TensorFlow Lite** model for sequence-based anomaly detection (LSTM or 1D-CNN on log embeddings), ~30 MB RSS.

3. **Rule engine for known signatures** — Regex/pattern rules for known bad states (PPPoE `PADT` storms, DHCP `NAK` floods, `link down` frequency). This is deterministic and nearly zero-cost.

4. **SQLite time-series store** — Rolling 24–48 hours of aggregated metrics (event counts per category per 5-min bucket). ~5–10 MB on disk. Enables trend detection for predictive warnings.

5. **Alert output** — Local MQTT publish, or HTTP POST to a webhook on your desktop, or write to a local unix socket.

**Memory budget:**

| Component | RAM |
|---|---|
| Fluent Bit | ~15 MB |
| Anomaly detector (Python + ONNX) | ~40 MB |
| Rule engine (embedded in detector) | ~0 MB |
| SQLite | ~5 MB |
| Overhead / buffers | ~20 MB |
| **Total** | **~80 MB** |

This fits within your 150 MB budget with headroom.

**Limitations:** No LLM-based root-cause explanation. Diagnosis is limited to pattern-matching rules and statistical anomalies. No natural-language reports.

---

### Option B: Desktop-Only (CPE Ships Logs, All AI on Desktop)

**CPE side — minimal footprint (~5 MB RAM):**

1. Configure CPE's built-in **rsyslog** or **syslog-ng** to forward to your desktop via TCP/TLS syslog (RFC 5424) or use Fluent Bit as a lightweight forwarder.

**Desktop side — Docker Compose stack:**

1. **Log ingestion & storage:**
   - **Grafana Loki** — lightweight log aggregation, accepts syslog input. Stores logs with labels, supports LogQL queries.
   - Alternative: **OpenSearch** (heavier, but full-text search + dashboards built in).

2. **AI analysis engine (the core):**
   - **Ollama** running a small local LLM (e.g., Llama 3.1 8B, Mistral 7B, or Phi-3 Mini 3.8B) — these run well on a desktop with 16 GB RAM and a modest GPU.
   - A **Python service** that:
     - Periodically queries Loki for recent logs (last N minutes).
     - Extracts features (error rates, event sequences, timing patterns).
     - Runs statistical anomaly detection (Isolation Forest / Prophet for time-series).
     - Sends log context to the local LLM for **natural-language root-cause diagnosis** ("The PPPoE session dropped 5 times in the last hour, correlating with CRC error spikes on the DSL interface — likely a line quality issue").
     - Generates **predictive warnings** by fitting trend models on rolling metrics.

3. **Dashboard & alerting:**
   - **Grafana** — dashboards for log volume, error rates, anomaly scores, LLM-generated diagnosis.
   - Grafana alerting rules → email, Slack webhook, or desktop notification.

4. **Health report generation:**
   - Scheduled job (cron or Celery beat) that asks the LLM to summarize the last 24h of CPE health into a structured report.

**Docker Compose services:**

| Service | Image | Purpose |
|---|---|---|
| `loki` | grafana/loki | Log storage |
| `promtail` or syslog input | grafana/promtail | Syslog receiver → Loki |
| `grafana` | grafana/grafana | Dashboards & alerts |
| `ollama` | ollama/ollama | Local LLM inference |
| `analyzer` | Custom Python image | Feature extraction + anomaly detection + LLM orchestration |

**Advantages:** Full LLM power for diagnosis. Rich dashboards. Easy to iterate on prompts and models.

---

### Option C: Hybrid (Recommended for Production)

Best of both — lightweight agent on CPE, heavy analysis on desktop.

**CPE agent Docker container (~60–80 MB RAM):**

1. **Fluent Bit** — parse and forward raw logs to desktop, plus local buffering if connection drops.
2. **Lightweight anomaly detector** — same Isolation Forest / ONNX model from Option A. Runs locally for **real-time** alerts (sub-second latency; doesn't depend on network).
3. **Pre-filter & enrich** — tag logs with anomaly scores, add CPE metadata (model, firmware version, uptime, interface stats from `/proc` or TR-069 data model). Forward enriched logs to desktop.
4. **Local alert actions** — if anomaly score exceeds threshold, immediately raise alert (MQTT, LED blink, TR-069 inform). This gives instant edge alerting.

**Desktop server (~same as Option B):**

1. Receives enriched logs from CPE agent.
2. Runs deeper analysis: LLM-based root-cause diagnosis, trend prediction, health reports.
3. Grafana dashboards.
4. Can push recommended remediation actions back to the CPE agent (for future auto-remediation phase).

**Communication protocol:** CPE → Desktop over **HTTP/gRPC** or **syslog-over-TLS**. Desktop → CPE over **MQTT** or **REST API** (for future remediation commands).

---

### Steps to Build (for all options)

1. **Define the log schema** — catalog every log type the CPE emits: syslog facility/severity, DHCP events (DISCOVER, OFFER, REQUEST, ACK, NAK), PPPoE states (PADI, PADO, PADR, PADS, PADT), Wi-Fi assoc/deauth, kernel messages. Build a regex parser for each.

2. **Collect baseline data** — run the CPE normally for 1–2 weeks, capture all logs. This becomes your "normal" training set.

3. **Build the anomaly detection model:**
   - Feature engineering: compute per-5-minute aggregates (event count by type, error ratio, unique MACs, session duration stats).
   - Train Isolation Forest on the baseline. Export to ONNX.
   - For time-series prediction: fit Facebook Prophet or a simple ARIMA on error-rate trends.

4. **Write the rule engine** — encode known failure signatures:
   - `PPPoE PADT` > 3 times in 10 min → "PPPoE instability"
   - `DHCP NAK` for same client > 5 times → "DHCP pool exhaustion or config mismatch"
   - `kernel: link down` followed by `link up` within 30s, repeated → "link flapping"
   - CRC/FEC error rate increasing linearly over hours → "line degradation, predict dropout"

5. **Build the CPE Docker container** (for Options A & C):
   - Base: `arm64v8/python:3.11-slim` or `arm64v8/alpine` + compiled Go binary
   - Include: Fluent Bit config, ONNX runtime, anomaly model, rule engine
   - Resource limits: `--memory=120m` to enforce budget

6. **Build the desktop Docker Compose stack** (for Options B & C):
   - Loki + Grafana + Ollama + custom Python analyzer
   - Write the analyzer service: poll Loki → extract features → detect anomalies → prompt LLM → store results → surface in Grafana

7. **Design the LLM prompt chain** (for desktop analysis):
   - **Prompt 1 (Summarize):** "Given these CPE logs from the last hour, identify all notable events and anomalies."
   - **Prompt 2 (Diagnose):** "Given these anomalies: [list], explain the most likely root cause for each."
   - **Prompt 3 (Predict):** "Given this trend data: [metrics], predict whether any service degradation is likely in the next 6–24 hours."
   - Use structured output (JSON mode) for machine-parseable results.

8. **Build Grafana dashboards:**
   - Panel 1: Log volume over time by category
   - Panel 2: Anomaly score timeline
   - Panel 3: LLM diagnosis feed (text panel)
   - Panel 4: Predictive warning indicators
   - Panel 5: CPE health summary card

9. **Test with synthetic failure scenarios:**
   - Inject PPPoE flap logs, DHCP exhaustion logs, simulated line degradation
   - Verify anomaly detection fires, LLM diagnoses correctly, predictions trigger

### Verification

- **On CPE:** run `docker stats` to confirm container stays under 120 MB RSS. Inject test logs via `logger -p local0.err "test error"` and verify anomaly detection fires.
- **On desktop:** check Grafana dashboards populate, LLM diagnosis appears within ~30s of anomaly, health report generates on schedule.
- **End-to-end:** disconnect CPE WAN, observe log burst, verify alert triggers on CPE (edge) and diagnosis appears on desktop (deeper analysis).

### Decisions

- **Alerting only for now** — remediation hooks (MQTT command channel from desktop → CPE) are architecturally planned but not implemented in phase 1.
- **Desktop instead of cloud** — Ollama replaces cloud LLM APIs; Loki+Grafana replaces CloudWatch/equivalent. Can migrate to cloud later by swapping endpoints.
- **Fluent Bit over Vector** — chosen for lower memory footprint on CPE (~15 MB vs ~30 MB).
- **Isolation Forest for anomaly detection** — simple, unsupervised, low-resource. Can upgrade to LSTM-based model later if needed.
