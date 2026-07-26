FROM python:3.13-slim

ARG BAIT_UID=10001
ARG BAIT_GID=10001

RUN groupadd --gid "${BAIT_GID}" bait \
    && useradd --uid "${BAIT_UID}" --gid "${BAIT_GID}" --create-home bait

WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY bait_edr ./bait_edr
COPY rules ./rules
COPY config.example.yml ./config.example.yml

RUN python -m pip install --no-cache-dir . \
    && mkdir -p /app/data \
    && chown -R bait:bait /app

USER bait
ENV BAIT_CONFIG=/app/config.yml \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

VOLUME ["/app/data"]
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=4s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/health', timeout=3).read()" || exit 1

CMD ["bait", "serve", "--host", "0.0.0.0", "--port", "8765"]
