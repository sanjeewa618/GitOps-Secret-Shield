import os
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()


class Settings(BaseModel):
    PROJECT_NAME: str = "GitOps Secret Shield"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    
    # GitHub Webhook
    GITHUB_WEBHOOK_SECRET: str = os.getenv("GITHUB_WEBHOOK_SECRET", "your_local_test_secret_change_me")
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
    
    # HashiCorp Vault
    VAULT_ADDR: str = os.getenv("VAULT_ADDR", "http://localhost:8200")
    VAULT_TOKEN: str = os.getenv("VAULT_TOKEN", "root")
    
    # Database (Port 5434 to avoid conflict with existing local postgres containers)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql+psycopg2://postgres:postgres@localhost:5434/secret_shield")

    # JWT Authentication (Phase 2)
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "CHANGE_ME_IN_PRODUCTION_JWT_SECRET")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "AdminSecret123!")
    DEV_PASSWORD: str = os.getenv("DEV_PASSWORD", "DevPassword456!")

    # Rate Limiting (Phase 2)
    RATE_LIMIT_REQUESTS: int = int(os.getenv("RATE_LIMIT_REQUESTS", "60"))
    RATE_LIMIT_WINDOW_S: int = int(os.getenv("RATE_LIMIT_WINDOW_S", "60"))
    RATE_LIMIT_AUTH_REQUESTS: int = int(os.getenv("RATE_LIMIT_AUTH_REQUESTS", "10"))

    # Email Alerting (Phase 2)
    ALERT_EMAIL_ENABLED: bool = os.getenv("ALERT_EMAIL_ENABLED", "false").lower() == "true"
    ALERT_EMAIL_FROM: str = os.getenv("ALERT_EMAIL_FROM", "gitops-shield@example.com")
    ALERT_EMAIL_TO: str = os.getenv("ALERT_EMAIL_TO", "security-team@example.com")
    ALERT_SMTP_HOST: str = os.getenv("ALERT_SMTP_HOST", "localhost")
    ALERT_SMTP_PORT: int = int(os.getenv("ALERT_SMTP_PORT", "587"))
    ALERT_SMTP_TLS: bool = os.getenv("ALERT_SMTP_TLS", "true").lower() == "true"
    ALERT_SMTP_USER: str = os.getenv("ALERT_SMTP_USER", "")
    ALERT_SMTP_PASS: str = os.getenv("ALERT_SMTP_PASS", "")

    # Slack Alerting (Phase 2)
    ALERT_SLACK_ENABLED: bool = os.getenv("ALERT_SLACK_ENABLED", "false").lower() == "true"
    ALERT_SLACK_WEBHOOK_URL: str = os.getenv("ALERT_SLACK_WEBHOOK_URL", "")

    @property
    def SQLALCHEMY_DATABASE_URI(self) -> str:
        """Ensure standard postgresql:// URLs use psycopg2 dialect driver."""
        if self.DATABASE_URL.startswith("postgresql://"):
            return self.DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)
        return self.DATABASE_URL


settings = Settings()
