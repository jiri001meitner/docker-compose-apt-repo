# aptly + repo-sync. Ubuntu 26.04 (aptly 1.6); the tag floats over point
# releases and the image is rebuilt by `up`. `ubuntu:latest` still points to
# 24.04 with aptly 1.5.
FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    LC_ALL=C.UTF-8

RUN apt-get update \
    && apt-get install -y --no-install-recommends aptly gnupg ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10200 aptly \
    && useradd --system --uid 10200 --gid aptly --home-dir /var/lib/aptly --shell /usr/sbin/nologin aptly

COPY repo_sync/ /app/repo_sync/
RUN python3 -m compileall -q /app/repo_sync

USER 10200:10200
ENTRYPOINT ["python3", "-m", "repo_sync"]
CMD ["sync"]
