from pydantic_settings import SettingsConfigDict

from fail2banexporter import config


def test_settings_initializes():
    settings = config.Settings()
    assert settings.server.port == 0


def test_settings_loads_environment_variables(monkeypatch):
    monkeypatch.setenv("F2B_GEO_SERVER__PORT", "5000")
    settings = config.Settings()
    assert settings.server.port == 5000


def test_settings_loads_yaml(tmp_path):
    yaml_fpath = tmp_path / "config.yaml"
    yaml_fpath.write_text(
        """
server:
    listen_address: pytest
    port: 5001
"""
    )

    # idk a better way to mock this?
    class TestSettings(config.Settings):
        model_config = SettingsConfigDict(yaml_file=yaml_fpath)

    settings = TestSettings()
    assert settings.server.port == 5001
