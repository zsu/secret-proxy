# The gateway owns the network namespace, the secrets, the CA key and the proxy.
FROM python:3.13-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends iptables \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 999 --create-home --shell /usr/sbin/nologin mitm
# Install the package (and mitmproxy) from pyproject.toml.
COPY pyproject.toml README.md /src/secret-proxy/
COPY src /src/secret-proxy/src
RUN pip install --no-cache-dir /src/secret-proxy && rm -rf /src/secret-proxy
COPY deploy/gateway/addon_entry.py /opt/secretproxy/addon_entry.py
COPY deploy/gateway/entrypoint.sh /entrypoint.sh
# Upstream trust = public roots (certifi) + the demo's "public" test CA used by fakeapi.
COPY deploy/runtime/certs/public-test-ca.pem /tmp/public-test-ca.pem
RUN mkdir -p /etc/secretproxy \
 && cat "$(python -c 'import certifi; print(certifi.where())')" /tmp/public-test-ca.pem \
      > /etc/secretproxy/upstream-ca.pem \
 && sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["/entrypoint.sh"]
