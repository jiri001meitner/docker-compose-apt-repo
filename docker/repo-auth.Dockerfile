# repo-auth (Caddy forward_auth over a UNIX socket) and repo-admin.
# Standard library only: no third-party Python packages in the image.
FROM python:3-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

COPY repo_auth/ /app/repo_auth/
RUN printf '#!/bin/sh\nexec python -m repo_auth.admin "$@"\n' > /usr/local/bin/repo-admin \
    && chmod 0755 /usr/local/bin/repo-admin \
    && python -m compileall -q /app/repo_auth

USER 65534:65534
ENTRYPOINT ["python", "-m", "repo_auth.server"]
