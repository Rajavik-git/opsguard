# Multi-stage, non-root, read-only-friendly image (OpenShift compatible: arbitrary UID, group 0).
FROM python:3.12-slim AS build
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install ".[all]"

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OPSGUARD_HOME=/app
WORKDIR /app
COPY --from=build /install /usr/local
COPY config ./config
COPY data ./data
COPY redteam ./redteam
RUN useradd --uid 10001 --gid 0 --no-create-home opsguard && chgrp -R 0 /app && chmod -R g=u /app
USER 10001
ENTRYPOINT ["opsguard"]
CMD ["mcp"]
