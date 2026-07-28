FROM python:3.12.5-slim AS builder
WORKDIR /build
COPY pyproject.toml ./
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12.5-slim
RUN groupadd --system inspector && useradd --system --gid inspector --home /app inspector
WORKDIR /app
COPY --from=builder /install /usr/local
COPY app ./app
USER inspector
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"]

