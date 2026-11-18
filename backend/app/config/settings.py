import os
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()


class Settings(BaseModel):
    PROJECT_NAME: str = "GitOps Secret Shield"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    
    # GitHub Webhook
    GITHUB_WEBHOOK_SECRET: str = os.getenv("GITHUB_WEBHOOK_SECRET", "change-me-secret")
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
    
    # HashiCorp Vault
    VAULT_ADDR: str = os.getenv("VAULT_ADDR", "http://localhost:8200")
    VAULT_TOKEN: str = os.getenv("VAULT_TOKEN", "root")
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/secret_shield")


settings = Settings()
