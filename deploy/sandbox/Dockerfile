# The agent's box. It knows nothing about a proxy: no HTTPS_PROXY, no base URLs.
# The only proxy-related thing is that the image trusts the proxy CA, the same
# way a corporate laptop trusts its TLS-inspection CA.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl python3 iproute2 \
 && rm -rf /var/lib/apt/lists/*
# Public cert only - the CA private key never enters this image.
COPY deploy/runtime/ca/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/secretproxy.crt
# Stand-in for a real public root (signs the demo's fakeapi upstream).
COPY deploy/runtime/certs/public-test-ca.pem /usr/local/share/ca-certificates/public-test-ca.crt
RUN update-ca-certificates
# Runtimes that ship their own CA store need to be pointed at the system bundle.
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/secretproxy.crt
RUN useradd --uid 1000 --create-home agent
COPY deploy/sandbox/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh
WORKDIR /home/agent
ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]
