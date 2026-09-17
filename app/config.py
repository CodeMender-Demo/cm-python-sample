import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings:
    """Application runtime configuration."""

    APP_NAME: str = "FinPulse Enterprise Portal API"
    APP_VERSION: str = "1.2.0"
    DEBUG: bool = True

    # Database configuration
    DATABASE_PATH: str = os.getenv(
        "FINPULSE_DB_PATH", str(BASE_DIR / "data" / "finpulse.db")
    )

    # Storage directories for invoices, receipts, and report templates
    STORAGE_ROOT: Path = Path(
        os.getenv("FINPULSE_STORAGE_ROOT", str(BASE_DIR / "storage"))
    )
    DOCUMENTS_BASE_DIR: Path = STORAGE_ROOT / "documents"
    TEMPLATES_DIR: Path = STORAGE_ROOT / "templates"

    # External integration settings
    DEFAULT_EXCHANGE_RATE_URL: str = "https://api.exchangerate-api.com/v4/latest/USD"
    WEBHOOK_TIMEOUT_SECONDS: int = 5


settings = Settings()
