FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    net-tools \
    tcpdump \
    iperf3 \
    python3 \
    python3-pip \
    python3-scapy \
    curl \
    ca-certificates \
    build-essential \
    gdb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
CMD ["sleep", "infinity"]
