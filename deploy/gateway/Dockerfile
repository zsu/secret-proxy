# secretproxy gateway appliance: proxy + egress rules + DNS for the sandbox network.
# Generic image: config, CA, secrets and (optionally) an upstream CA bundle are
# mounted at run time, so the same image serves the Docker demo and a gateway VM.
#
#   docker build -f deploy/gateway/Dockerfile -t secretproxy-gateway .
FROM python:3.13-slim
# Fixed non-system uid/gid 10001 for the proxy (Kubernetes runAsUser, file ownership
# of mounted CA/secrets on a host). Created first so no package can take the id.
RUN groupadd --gid 10001 mitm \
 && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin mitm
RUN apt-get update \
 && apt-get install -y --no-install-recommends iptables iproute2 dnsmasq-base \
 && rm -rf /var/lib/apt/lists/*
# Install the package (and mitmproxy) from pyproject.toml.
COPY pyproject.toml README.md /src/secret-proxy/
COPY src /src/secret-proxy/src
RUN pip install --no-cache-dir /src/secret-proxy && rm -rf /src/secret-proxy
COPY deploy/scripts/egress-rules.sh /usr/local/sbin/egress-rules.sh
COPY deploy/gateway/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh /usr/local/sbin/egress-rules.sh \
 && chmod +x /entrypoint.sh /usr/local/sbin/egress-rules.sh \
 && mkdir -p /etc/secretproxy
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["/entrypoint.sh"]
