# account-unification admin service image.
FROM python:3.12-slim@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /srv

COPY requirements.txt ./

RUN python -m pip install --no-cache-dir --require-hashes -r requirements.txt \
    && adduser --system --no-create-home appuser

COPY app ./app

USER appuser
EXPOSE 8099

# The ONLY env var is the bootstrap pointer; real config comes from the KV store.
ENV CWL_IDP_BOOTSTRAP=/bootstrap/bootstrap.yaml

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD ["python", "-m", "app.healthcheck"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8099"]
