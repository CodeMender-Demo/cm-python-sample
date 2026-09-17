from contextlib import asynccontextmanager
from fastapi import FastAPI

from app.config import settings
from app.db.database import init_db_and_storage
from app.routers import documents, integrations, invoices, reports


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize SQLite schema, seed data, and storage directories on startup."""
    init_db_and_storage()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "FinPulse Enterprise Portal API for managing client invoices, financial document archives, "
        "external webhook integrations, and executive audit reports."
    ),
    lifespan=lifespan,
)

# Register API routers
app.include_router(invoices.router)
app.include_router(documents.router)
app.include_router(integrations.router)
app.include_router(reports.router)


@app.get("/", tags=["Health"])
def root():
    """Service health check and API overview."""
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "operational",
        "docs_url": "/docs",
    }
