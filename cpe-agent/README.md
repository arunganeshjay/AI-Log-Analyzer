# CPE Agent - Fluent Bit Log Forwarder

Lightweight log collector and forwarder for ARM-based broadband CPE devices.

## Build (on ARM device or with cross-compilation)

```bash
docker build -t ai-log-analyzer/cpe-agent:latest .
```

## Run

```bash
docker run -d \
  --name cpe-agent \
  --memory=30m \
  -v /var/log/syslog:/var/log/syslog:ro \
  -e CPE_ID=cpe-001 \
  -e CPE_MODEL=my-router \
  -e FIRMWARE_VERSION=2.1.0 \
  -e DESKTOP_HOST=192.168.1.100 \
  -e DESKTOP_PORT=8080 \
  -p 5140:5140/udp \
  ai-log-analyzer/cpe-agent:latest
```

## Testing locally

Send a test syslog message to the agent:

```bash
echo "<134>Feb 20 10:00:00 cpe pppd[1234]: PPPoE session terminated" | nc -u -w1 localhost 5140
```

## Health check

```bash
curl http://localhost:2020/api/v1/health
```
