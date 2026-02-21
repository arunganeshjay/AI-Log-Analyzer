FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY analyzer.py rules.py ./

# Data volume for SQLite
RUN mkdir -p /data
VOLUME /data

ENV PORT=8080
ENV DB_PATH=/data/analyzer.db
ENV LOG_LEVEL=INFO
ENV METRICS_WINDOW_SEC=300

EXPOSE 8080

CMD ["python", "analyzer.py"]
