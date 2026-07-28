FROM python:3.12.5-slim
RUN groupadd --system mitmproxy && useradd --system --gid mitmproxy --uid 10001 --home /home/mitmproxy --create-home mitmproxy
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY inspector_addon.py healthcheck.py guard.py entrypoint.sh ./
RUN chmod 755 /app/entrypoint.sh
RUN mkdir -p /home/mitmproxy/.mitmproxy /var/lib/traffic-inspector/spool /var/lib/traffic-inspector/state /var/lib/traffic-inspector/bodies \
    && chown -R mitmproxy:mitmproxy /home/mitmproxy /var/lib/traffic-inspector/spool /var/lib/traffic-inspector/state \
    && chown -R mitmproxy:999 /var/lib/traffic-inspector/bodies \
    && chmod 770 /var/lib/traffic-inspector/bodies
USER mitmproxy
ENTRYPOINT ["/app/entrypoint.sh"]
EXPOSE 51820/udp
