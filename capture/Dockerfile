FROM python:3.12.5-slim
RUN groupadd --system mitmproxy && useradd --system --gid mitmproxy --uid 10001 --home /home/mitmproxy --create-home mitmproxy
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY inspector_addon.py healthcheck.py ./
RUN mkdir -p /var/lib/traffic-inspector/spool /var/lib/traffic-inspector/state && chown -R mitmproxy:mitmproxy /var/lib/traffic-inspector /home/mitmproxy
USER mitmproxy
EXPOSE 51820/udp

