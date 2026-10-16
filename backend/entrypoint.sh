#!/bin/sh
# Bring the database schema up to date, then run the container's command (uvicorn by default).
# Living in the image, this applies however the image is started, not only through Compose.
set -e
alembic upgrade head
exec "$@"
