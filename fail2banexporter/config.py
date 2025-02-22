import pathlib

from pydantic import BaseModel, field_validator
from pydantic_core.core_schema import ValidationInfo
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)


class ServerConfig(BaseModel):
    listen_address: str | None = ""
    port: int | None = 0

    @field_validator("listen_address", "port")
    @classmethod
    def none_to_default(cls, v: str, info: ValidationInfo):
        if v is None:
            return cls.model_fields[info.field_name].default
        return v


class GeoConfig(BaseModel):
    enabled: bool = True
    provider: str = "MaxmindDB"
    enable_grouping: bool = True
    maxmind_dbpath: pathlib.Path = "/f2b-exporter/db/GeoLite2-City.mmdb"


class Fail2banConfig(BaseModel):
    conf_path: pathlib.Path = "/etc/fail2ban"
    db_path: pathlib.Path = "/var/lib/fail2ban/fail2ban.sqlite3"


class Settings(BaseSettings):
    server: ServerConfig = ServerConfig()
    geo: GeoConfig = GeoConfig()
    fail2ban: Fail2banConfig = Fail2banConfig()

    model_config = SettingsConfigDict(
        env_prefix="F2B_GEO_",
        env_nested_delimiter="__",
        yaml_file="conf.yml",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return env_settings, YamlConfigSettingsSource(settings_cls), init_settings
