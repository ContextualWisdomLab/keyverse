# account-unification admin service image.
FROM python:3.14-slim@sha256:b877e50bd90de10af8d82c57a022fc2e0dc731c5320d762a27986facfc3355c1

COPY --from=ghcr.io/astral-sh/uv@sha256:5c3ab83183a73c5d319a77009eb425b60d5bb937f339fb7876788ebf567baf48 \
    /uv /usr/local/bin/uv

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/srv/.venv/bin:$PATH"

WORKDIR /srv

COPY pyproject.toml uv.lock ./

RUN uv sync --locked --no-dev --no-install-project \
    && adduser --system --no-create-home appuser

COPY app ./app

USER appuser
EXPOSE 8099

# The ONLY env var is the bootstrap pointer; real config comes from the KV store.
ENV CWL_IDP_BOOTSTRAP=/bootstrap/bootstrap.yaml

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD ["python", "-m", "app.healthcheck"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8099"]
