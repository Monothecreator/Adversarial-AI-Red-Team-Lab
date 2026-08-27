from pydantic import BaseModel


class Settings(BaseModel):
    app_name: str = "adversarial-ai-red-team-lab"
    app_env: str = "development"
    app_port: int = 8000
    log_level: str = "INFO"


settings = Settings()
