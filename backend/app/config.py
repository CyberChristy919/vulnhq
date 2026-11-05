from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Loaded from backend/.env (DATABASE_URL, NVD_API_KEY)
    database_url: str
    nvd_api_key: str = ""

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()