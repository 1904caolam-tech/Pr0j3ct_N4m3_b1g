# One image, two targets:
#   app     — API + UI (default), no scanner binaries
#   scanner — app + nuclei/trivy/gitleaks/yara for `p4b scan`
#
# The split exists so the long-running API image stays small and does not ship
# offensive tooling it never runs.

# syntax=docker/dockerfile:1
FROM python:3.12-slim AS app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    P4B_DATA_DIR=/data \
    P4B_HOST=0.0.0.0 \
    P4B_PORT=8080 \
    P4B_MIGRATIONS=/app/migrations

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./
COPY demo ./demo

RUN pip install . \
 && useradd --create-home --uid 10001 p4b \
 && mkdir -p /data \
 && chown -R p4b:p4b /data /app

USER p4b
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health', timeout=3)"

ENTRYPOINT ["p4b"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]


FROM app AS scanner

# Pinned on purpose: scanners change output formats between minor releases, and the
# parsers here are written against specific shapes. Bump deliberately, then run the
# golden tests against real output.
ARG TRIVY_VERSION=0.76.2
ARG NUCLEI_VERSION=3.11.1
ARG GITLEAKS_VERSION=8.30.1

USER root

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip yara \
 && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    curl -fsSL -o /tmp/trivy.tgz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
    tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy; \
    curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"; \
    unzip -q /tmp/nuclei.zip -d /usr/local/bin nuclei; \
    curl -fsSL -o /tmp/gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; \
    tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; \
    rm -f /tmp/trivy.tgz /tmp/nuclei.zip /tmp/gitleaks.tgz; \
    trivy --version; nuclei -version; gitleaks version; yara --version

USER p4b

ENTRYPOINT ["p4b"]
CMD ["--help"]
