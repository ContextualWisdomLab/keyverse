FROM scratch
USER 65532:65532
HEALTHCHECK NONE

# ClusterFuzzLite discovery marker for Scorecard and central coverage builds.
# The central coverage gate builds .clusterfuzzlite with this directory as the
# Docker context, so root-relative COPY instructions cannot succeed here. The
# actual account-unification runtime image remains services/account_unification/Dockerfile,
# and the fuzz entrypoint remains services/account_unification/fuzz/fuzz_matching.py.
