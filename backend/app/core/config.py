from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "AI-Driven SOC"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    ALLOWED_ORIGINS: list[str] = ["http://localhost:5173"]

    # Minimum Wazuh rule level for an alert to be considered a "useful" event
    # and enter the pipeline. Wazuh levels run 0-15; 7+ covers attacks/notables.
    # This is the global default; tenants can override it (see app.services.tenants).
    MIN_ALERT_LEVEL: int = 7

    # Ingest worker cadence. Defaults suit normal monitoring; raise the batch and
    # lower the poll for load/throughput testing so the SOC keeps pace with bursts.
    INGEST_POLL_SECONDS: int = 15
    INGEST_BATCH_SIZE: int = 10

    # Postgres connection (tenant registry + settings).
    DATABASE_URL: str = "postgresql+psycopg://soc:soc@localhost:5432/soc"

    # ── Auth ──────────────────────────────────────────────────────────────────
    # Secret used to sign JWT access tokens. Override in .env for any real deploy.
    SECRET_KEY: str = "dev-insecure-secret-key-change-me-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 12  # 12h
    JWT_ALGORITHM: str = "HS256"

    # Admin account seeded on first boot when the user table is empty.
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "admin"  # change in .env before any real deploy

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"  # .env also holds Wazuh creds consumed by WazuhClient


settings = Settings()
