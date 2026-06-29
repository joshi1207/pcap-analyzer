FROM python:3.12-slim

ARG TARGETARCH
ARG GTRACE_VERSION=0.10.1

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    iputils-ping \
    tshark \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64|arm64) ;; \
      *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    archive="gtrace_${GTRACE_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    base_url="https://github.com/hervehildenbrand/gtrace/releases/download/v${GTRACE_VERSION}"; \
    curl -fsSL "${base_url}/${archive}" -o "/tmp/${archive}"; \
    curl -fsSL "${base_url}/checksums.txt" -o /tmp/checksums.txt; \
    cd /tmp; \
    grep " ${archive}$" checksums.txt | sha256sum -c -; \
    tar -xzf "${archive}"; \
    install -m 0755 gtrace /usr/local/bin/gtrace; \
    rm -f "${archive}" checksums.txt gtrace; \
    gtrace --version

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY tools ./tools

RUN mkdir -p \
    /app/data/uploads \
    /app/data/results \
    /app/data/gtrace_results \
    /app/data/gtrace_info_cache

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
