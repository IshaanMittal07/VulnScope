"""FastAPI application entry point."""

from fastapi import FastAPI

from app.api import health, targets

app = FastAPI(title="VulnScope", version="0.1.0")
app.include_router(health.router)
app.include_router(targets.router)
