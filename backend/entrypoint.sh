#!/bin/sh
set -e

# Threaded workers = no gevent dependency
exec gunicorn \
  --worker-class gthread \
  --workers ${WEB_CONCURRENCY:-2} \
  --threads ${WEB_THREADS:-8} \
  --timeout ${WEB_TIMEOUT:-120} \
  --log-level info \
  -b 0.0.0.0:${PORT:-8000} \
  app:app