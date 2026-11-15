"""Cloudflare Python Worker entrypoint for the R&MA FastAPI application."""

import os

# Set this before importing app.main so SQLite auto-creation and real local
# WireGuard command paths are disabled in the Worker runtime.
os.environ["RMA_CLOUDFLARE_WORKER"] = "1"

from workers import WorkerEntrypoint, asgi

from app.config import activate_worker_settings, reset_worker_settings
from app.main import app


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        token = activate_worker_settings(self.env)
        try:
            # The ASGI adapter injects self.env into request.scope["env"] so
            # FastAPI dependencies can access the Hyperdrive binding safely.
            return await asgi.fetch(app, request, self.env)
        finally:
            reset_worker_settings(token)
