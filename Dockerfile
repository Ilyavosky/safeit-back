FROM golang:1.24-bookworm AS tools
ENV CGO_ENABLED=0 GOBIN=/out
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.7 \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@v1.6.10 \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.10 \
 && mv /out/httpx /out/pd-httpx

FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_PROJECT_ENVIRONMENT=/opt/venv
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap git openssl bsdmainutils dnsutils procps ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && git clone --depth 1 --branch v3.2.0 https://github.com/testssl/testssl.sh.git /opt/testssl \
 && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh \
 && rm -rf /opt/testssl/.git
COPY --from=tools /out/ /usr/local/bin/
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY app ./app
COPY scripts ./scripts

RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin scanner \
 && mkdir -p /tmp/scanner \
 && HOME=/tmp/scanner nuclei -ut -silent >/dev/null 2>&1 || true
RUN chown -R scanner /tmp/scanner
USER scanner
ENV PATH="/opt/venv/bin:$PATH" HOME=/tmp/scanner TMPDIR=/tmp/scanner HTTPX_BIN=pd-httpx PORT=8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --no-proxy-headers"]
