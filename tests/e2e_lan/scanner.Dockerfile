# Network audit E2E: the auditor's machine (docs/research/network_audit.md §10). CI only.
FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap iproute2 util-linux \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 1000 auditor
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
ENV PYTHONDONTWRITEBYTECODE=1
