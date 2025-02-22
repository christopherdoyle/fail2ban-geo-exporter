"""Parsers for the fail2ban configuration files in /etc/fail2ban."""

import configparser
import pathlib


def read(root_directory: str | pathlib.Path = "/etc/fail2ban"):
    root_directory = pathlib.Path(root_directory)
    config = configparser.ConfigParser()
    config.read(root_directory / "jail.local")
    config.read((root_directory / "jail.d").glob("*.local"))
    return config


def read_jail_bantime(config, jail_name: str) -> int:
    bantime = int(config[jail_name]["bantime"].split(";")[0].strip())
    return bantime
