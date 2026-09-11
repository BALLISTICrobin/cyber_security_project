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
    iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY server/stream_server.c /work/stream_server.c
COPY server/defense_server.c /work/defense_server.c
RUN gcc -O2 -Wall -o /work/stream_server /work/stream_server.c && \
    gcc -O2 -Wall -o /work/defense_server /work/defense_server.c

# DEFENSE=on runs the skip-test defense server (M4); otherwise the plain
# streaming server (M1). Both listen on port 5000.
CMD ["sh", "-c", "if [ \"$DEFENSE\" = on ] || [ \"$DEFENSE\" = 1 ]; then exec /work/defense_server 5000; else exec /work/stream_server 5000; fi"]
