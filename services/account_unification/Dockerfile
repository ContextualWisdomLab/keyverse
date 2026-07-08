# account-unification admin service image.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /srv

COPY pyproject.toml README.md ./
COPY app ./app

RUN python -m pip install --no-cache-dir . \
    && adduser --system --no-create-home appuser

USER appuser
EXPOSE 8099

# The ONLY env var is the bootstrap pointer; real config comes from the KV store.
ENV CWL_IDP_BOOTSTRAP=/bootstrap/bootstrap.yaml

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD ["python", "-m", "app.healthcheck"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8099"]
