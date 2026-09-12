# The dashboard controls its SIBLING containers (server/attacker/observer)
# by running `docker compose ...` against the same Docker daemon the host
# uses -- the classic "Docker outside of Docker" pattern: mount the host's
# Docker socket in, and use the official docker CLI image as the base so the
# `docker compose` command is already present. Python (stdlib only, no pip
# packages) is added on top to run dashboard/server.py.
#
# No application code is COPYed in on purpose: docker-compose.yml bind-mounts
# the live project directory at the SAME absolute path inside this container
# as it has on the host (the `${PWD}:${PWD}` trick) -- required so that when
# this container's `docker compose` CLI submits build-context/volume paths to
# the daemon, they resolve to real paths the daemon can see. As a side
# effect, editing dashboard/*.py or static/* on the host is reflected
# immediately without rebuilding this image.
FROM docker:27-cli
RUN apk add --no-cache python3
