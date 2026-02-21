FROM fluent/fluent-bit:3.2-arm64

# Copy configuration
COPY fluent-bit.conf /fluent-bit/etc/fluent-bit.conf
COPY parsers.conf /fluent-bit/etc/parsers.conf

# Create buffer directory
RUN mkdir -p /var/log/fluent-bit

# Environment variables (override at runtime)
ENV CPE_ID=cpe-001
ENV CPE_MODEL=generic-cpe
ENV FIRMWARE_VERSION=1.0.0
ENV DESKTOP_HOST=host.docker.internal
ENV DESKTOP_PORT=8080

# Expose health-check and syslog-in ports
EXPOSE 2020 5140/udp

# Resource limits enforced via docker run --memory=30m
CMD ["/fluent-bit/bin/fluent-bit", "-c", "/fluent-bit/etc/fluent-bit.conf"]
