FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY simulator.py .

ENV ANALYZER_URL=http://analyzer:8080/api/v1/logs
ENV RATE=2
ENV SCENARIO=normal
ENV CPE_ID=cpe-sim-001

CMD ["python", "-u", "simulator.py"]
