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

    # Postgres connection (tenant registry + settings).
    DATABASE_URL: str = "postgresql+psycopg://soc:soc@localhost:5432/soc"

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"  # .env also holds Wazuh creds consumed by WazuhClient


settings = Settings()
