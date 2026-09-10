# A plain slim base, not a browser image: this service makes outbound HTTPS calls and
# writes small files, and nothing else. The smaller the process holding the credentials,
# the less there is in it to go wrong.
FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_FROZEN=1 \
    VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Dependencies first, in their own layer: application edits then rebuild in seconds
# rather than re-resolving the whole tree.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --no-install-project --no-dev

COPY src/ src/
RUN uv sync --no-dev

# Runtime state -- encrypted secrets and the signing key -- is written at runtime and must
# not live in the image layers. 0700 because a world-readable directory leaks which
# services each person has connected even when every file inside is unreadable.
RUN useradd --create-home --uid 10001 keyring \
    && mkdir -p /var/lib/keyring/secrets /var/lib/keyring/keys \
    && chown -R keyring:keyring /var/lib/keyring /app \
    && chmod 700 /var/lib/keyring/secrets /var/lib/keyring/keys
VOLUME ["/var/lib/keyring"]

USER keyring

ENV KEYRING_HOST=0.0.0.0 \
    KEYRING_PORT=8001 \
    KEYRING_SECRET_DIR=/var/lib/keyring/secrets \
    KEYRING_SIGNING_KEY_PATH=/var/lib/keyring/keys/signing.pem \
    KEYRING_LOG_FORMAT=json

EXPOSE 8001

# KEYRING_MASTER_KEY and KEYRING_ADMIN_TOKEN are deliberately NOT set here. Baking either
# into an image puts it in every layer, every registry, and every `docker history`.

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8001/healthy', timeout=4).status == 200 else 1)"

CMD ["keyring-api"]
