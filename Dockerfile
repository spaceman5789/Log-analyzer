# syntax=docker/dockerfile:1
# --- build wheel ------------------------------------------------------------
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

# --- runtime: minimal image, no compilers, non-root -----------------------
FROM python:3.12-slim
LABEL org.opencontainers.image.title="log-analyzer" \
      org.opencontainers.image.description="SSH brute force detector for auth.log / journald" \
      org.opencontainers.image.source="https://github.com/spaceman5789/Log-analyzer"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin analyzer

USER 10001
WORKDIR /work
ENTRYPOINT ["log-analyzer"]
CMD ["--help"]

# Example (auth.log mounted read-only; gid 4 = adm on Debian/Ubuntu):
#   docker build -t log-analyzer .
#   docker run --rm --read-only --cap-drop ALL --group-add 4 \
#     -v /var/log/auth.log:/logs/auth.log:ro log-analyzer analyze /logs/auth.log
