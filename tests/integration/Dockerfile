# Test-only image: the production aptly image plus tools to build a fixture
# upstream repository. Build with --build-arg BASE=<aptly image tag>.
ARG BASE=apt-repo/aptly:test
FROM ${BASE}
USER 0
RUN apt-get update \
    && apt-get install -y --no-install-recommends dpkg-dev apt-utils \
    && rm -rf /var/lib/apt/lists/*
COPY run.sh /it/run.sh
ENTRYPOINT ["/it/run.sh"]
