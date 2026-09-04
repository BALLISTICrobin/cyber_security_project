FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    net-tools \
    procps \
    tcpdump \
    iperf3 \
    python3 \
    python3-pip \
    curl \
    ca-certificates \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
CMD ["sleep", "infinity"]
