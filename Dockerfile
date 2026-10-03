# syntax=docker/dockerfile:1

# ---- Builder: compile the 7 security tools ----
FROM golang:1.23-bookworm AS tools

RUN apt-get update && apt-get install -y --no-install-recommends git curl && rm -rf /var/lib/apt/lists/*

ENV GOPATH=/go
ENV PATH="/go/bin:${PATH}"

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    nuclei -update-templates -silent || true

# ---- Runtime: backend API + cybog engine ----
FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends curl jq ca-certificates git && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Security tool binaries + nuclei templates from builder
COPY --from=tools /go/bin /usr/local/bin
COPY --from=tools /root/.config/nuclei /root/.config/nuclei
COPY --from=tools /root/.cache/nuclei /root/.cache/nuclei
RUN chmod +x /usr/local/bin/* || true

# Cybog engine + backend
COPY cybog/ ./cybog/
COPY backend/ ./backend/

RUN pip install --no-cache-dir -e ./cybog && \
    pip install --no-cache-dir -e ./backend

# Defaults; Railway dashboard overrides CYBOG_OUTPUT_ROOT with a volume mount
ENV CYBOG_RUNTIME=production \
    CYBOG_CONFIG_PATH=/app/cybog/config.yaml \
    CYBOG_OUTPUT_ROOT=/data/reports \
    API_RELOAD=false

WORKDIR /app/backend
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD curl -fsS "http://localhost:${PORT:-8000}/health" || exit 1

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
