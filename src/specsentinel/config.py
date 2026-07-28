from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SPECSENTINEL_", extra="ignore")

    environment: str = "production"
    max_schema_bytes: int = Field(default=2_000_000, ge=1_024, le=20_000_000)
    max_operations: int = Field(default=500, ge=1, le=5_000)
    request_timeout_seconds: float = Field(default=30.0, ge=1, le=120)
    allowed_origins: str = ""
    api_keys: str = ""
    bundle_signing_key: str = ""
    bundle_signing_key_id: str = "default"
    max_bundle_bytes: int = Field(default=8_000_000, ge=16_384, le=50_000_000)

    @property
    def api_key_set(self) -> frozenset[str]:
        return frozenset(value.strip() for value in self.api_keys.split(",") if value.strip())

    @property
    def origin_list(self) -> list[str]:
        return [value.strip() for value in self.allowed_origins.split(",") if value.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
