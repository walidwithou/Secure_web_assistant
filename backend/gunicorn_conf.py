"""
Gunicorn configuration for the Secure Web Assistant phishing API.

Run with:
    gunicorn -c gunicorn_conf.py app.main:app
"""

from __future__ import annotations

import multiprocessing

# ---------------------------------------------------------------------------
# Server socket
# ---------------------------------------------------------------------------
bind = "127.0.0.1:8000"
backlog = 2048

# ---------------------------------------------------------------------------
# Worker processes
# ---------------------------------------------------------------------------
worker_class = "uvicorn.workers.UvicornWorker"
workers = multiprocessing.cpu_count() * 2 + 1
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
keepalive = 5
timeout = 30
graceful_timeout = 30

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
accesslog = "-"
errorlog = "-"
loglevel = "info"
access_log_format = '%(h)s %(r)s %(s)s %(b)s %(D)s'