# ClusterFuzzLite image for account-unification Python fuzz targets.
FROM python:3.12-slim@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /src/services/account_unification

COPY services/account_unification/requirements.txt ./
COPY services/account_unification/fuzz-requirements.txt ./fuzz-requirements.txt

RUN python -m pip install --no-cache-dir --require-hashes -r requirements.txt \
    && python -m pip install --no-cache-dir --require-hashes -r fuzz-requirements.txt

COPY services/account_unification/app ./app
COPY services/account_unification/fuzz ./fuzz

CMD ["python", "fuzz/fuzz_matching.py", "-runs=1000"]
