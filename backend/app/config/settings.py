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

    @property
    def SQLALCHEMY_DATABASE_URI(self) -> str:
        """Ensure standard postgresql:// URLs use psycopg2 dialect driver."""
        if self.DATABASE_URL.startswith("postgresql://"):
            return self.DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)
        return self.DATABASE_URL


settings = Settings()
