"""FastAPI application entry point."""

from fastapi import FastAPI

from app.api import health, scans, targets, verifications

app = FastAPI(title="VulnScope", version="0.1.0")
app.include_router(health.router)
app.include_router(targets.router)
app.include_router(verifications.router)
app.include_router(scans.router)
