"""Parsers for the fail2ban configuration files in /etc/fail2ban."""

import configparser
import logging
import pathlib

logger = logging.getLogger(__name__)


def read(root_directory: str | pathlib.Path = "/etc/fail2ban"):
    root_directory = pathlib.Path(root_directory)
    config = configparser.ConfigParser()
    config.read(root_directory / "jail.local")
    loaded = config.read((root_directory / "jail.d").glob("*.local"))
    loaded += config.read((root_directory / "jail.d").glob("*.conf"))
    for filepath in loaded:
        logger.debug("Loaded fail2ban config '%s'", filepath)
    return config


def read_jail_bantime(config, jail_name: str) -> int:
    if jail_name not in config.sections():
        logger.warning("fail2ban config '%s' not found", jail_name)
        jail_name = "DEAFULT"
    bantime = int(config[jail_name]["bantime"].split(";")[0].strip())
    return bantime
