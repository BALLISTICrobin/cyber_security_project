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
    iptables \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY attacker/optack.c /work/optack.c
COPY attacker/optack_proto.py /work/optack_proto.py
RUN gcc -O2 -Wall -o /work/attack /work/optack.c

CMD ["sleep", "infinity"]
