# =============================================================================
# SIH26145 Zeek 7.x Passive Sensor Container
# Configured with Native JA4 TLS Fingerprinting and Continuous JSON Streaming
# =============================================================================
FROM zeek/zeek:7.0

USER root

# Install essential dependencies for network capture and utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    python3 \
    python3-pip \
    libpcap-dev \
    gcc \
    g++ \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Setup workspace directories
RUN mkdir -p /logs /pcaps /config /usr/local/zeek/share/zeek/site
WORKDIR /logs

# Install configuration and JA4 fingerprinting modules
COPY config/zeek/local.zeek /usr/local/zeek/share/zeek/site/local.zeek
COPY config/zeek/ja4.zeek /usr/local/zeek/share/zeek/site/ja4.zeek
COPY config/zeek/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV ZEEKPATH=".:/usr/local/zeek/share/zeek:/usr/local/zeek/share/zeek/policy:/usr/local/zeek/share/zeek/site"
ENV ZEEK_INTERFACE="eth0"
ENV ZEEK_LOG_DIR="/logs"

VOLUME ["/logs", "/pcaps"]

HEALTHCHECK --interval=5s --timeout=3s --retries=5 --start-period=3s \
  CMD zeek -v || exit 1

ENTRYPOINT ["/entrypoint.sh"]
