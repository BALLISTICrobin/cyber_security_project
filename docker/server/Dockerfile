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
COPY server/stream_server.c /work/stream_server.c
RUN gcc -O2 -Wall -o /work/stream_server /work/stream_server.c

CMD ["/work/stream_server", "5000"]
