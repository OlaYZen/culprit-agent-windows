# Culprit report-only agent — outbound-only, opens no listening ports.
#
# The agent monitors the HOST it runs on, so run the container in the host's PID
# and network namespaces (see docker-compose.yml / README). Sources that need
# the host's systemd (units, journal) or extra bind mounts degrade to an
# explicit "unavailable, because X" rather than breaking — the agent's honesty
# discipline is what makes a container deployment safe.
FROM python:3.12-slim

# iproute2 gives `ip` for adapter/route detail; systemd provides `journalctl`,
# which reads the host journal from files (no daemon needed) when /var/log/journal
# and /etc/machine-id are mounted. Everything else is psutil + the stdlib.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 systemd \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# psutil ships manylinux wheels for amd64/arm64, so no build toolchain is needed.
COPY requirements-agent.txt ./
RUN pip install --no-cache-dir -r requirements-agent.txt

# nvidia-ml-py (the `pynvml` module) lets the GPU collector's NVML backend read
# an NVIDIA GPU's utilisation, VRAM and per-process memory. Pure Python, no
# native deps; it only does anything when the container is run with `--gpus all`
# (which injects the driver's libnvidia-ml). A harmless no-op otherwise.
RUN pip install --no-cache-dir nvidia-ml-py

COPY version.json ./
COPY culprit/ ./culprit/
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Config comes from the environment (CULPRIT_HOST, CULPRIT_TOKEN, optional
# CULPRIT_INTERVAL / CULPRIT_INSECURE / CULPRIT_LOG_LEVEL); the entrypoint turns
# them into the agent's CLI arguments. `python -u` for unbuffered logs.
#
# CULPRIT_AGENT_DOCKER marks this image so culprit/updater.py's capability
# check names the real reason a remote update is refused ("running in the
# Docker image") -- the image has no .git anyway, but that would report the
# wrong reason (it reads as a cp -r bundle, not a container).
ENV PYTHONUNBUFFERED=1
ENV CULPRIT_AGENT_DOCKER=1
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
