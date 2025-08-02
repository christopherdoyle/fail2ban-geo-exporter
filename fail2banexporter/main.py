import logging
from collections import defaultdict
from dataclasses import dataclass, field
from wsgiref.simple_server import make_server

from prometheus_client import make_wsgi_app
from prometheus_client.core import REGISTRY, GaugeMetricFamily
from prometheus_client.registry import Collector

from . import fail2ban_configs
from .config import Settings
from .fail2ban_db import Fail2BanDatabaseInterface

logger = logging.getLogger(__name__)


@dataclass(slots=True, frozen=True)
class BannedIp:
    ip: str
    extra_data: dict = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class Jail:
    name: str
    ip_list: list[BannedIp] = field(default_factory=list)
    bantime: int = 0


class F2bCollector(Collector):
    def __init__(self, settings: Settings):
        self.settings = settings
        self.geo_provider = self._import_provider()
        self.jails = []
        self.extra_labels = sorted(self.geo_provider.get_labels())

    def _import_provider(self):
        if self.settings.geo.enabled:
            class_name = self.settings.geo.provider
            mod = __import__(
                f"fail2banexporter.geoip_provider.{class_name.lower()}",
                fromlist=[class_name],
            )
            return getattr(mod, class_name)(self.settings)
        else:
            from fail2banexporter.geoip_provider.base import BaseProvider

            return BaseProvider(self.settings)

    def get_jailed_ips(self):
        self.jails.clear()

        config = fail2ban_configs.read(self.settings.fail2ban.conf_path)

        with Fail2BanDatabaseInterface(self.settings.fail2ban.db_path) as db:
            for jail_name in db.fetch_active_jails():
                logger.debug("Reading jail '%s' details", jail_name)
                bantime = fail2ban_configs.read_jail_bantime(config, jail_name)
                jail = Jail(
                    name=jail_name,
                    ip_list=[
                        BannedIp(ip) for ip in db.fetch_banned_ips(jail_name, bantime)
                    ],
                    bantime=bantime,
                )
                self.jails.append(jail)

    def assign_location(self):
        for jail in self.jails:
            for banned_ip in jail.ip_list:
                logger.debug("Updating location for %s", banned_ip.ip)
                location_info = self.geo_provider.annotate(banned_ip.ip)
                if location_info is None:
                    logger.warning("Cannot assign location info for '%s'", banned_ip.ip)
                else:
                    banned_ip.extra_data.update(location_info)

    def collect(self):
        logger.info("Collecting")
        self.get_jailed_ips()
        logger.info("Found %d jails", len(self.jails))
        self.assign_location()

        if self.settings.geo.enable_grouping:
            yield self.expose_grouped()
            yield self.expose_jail_summary()
        else:
            yield self.expose_single()

    def expose_single(self):
        metric_labels = ["jail", "ip"] + self.extra_labels
        gauge = GaugeMetricFamily(
            "fail2ban_banned_ip", "IP banned by fail2ban", labels=metric_labels
        )

        for jail in self.jails:
            for banned_ip in jail.ip_list:
                # Skip if GeoProvider.annotate() did not return matching count of labels
                entry = {"ip": banned_ip.ip}
                entry.update(banned_ip.extra_data)
                if len(entry) < len(self.extra_labels) + 1:
                    continue
                values = [jail.name, entry["ip"]] + [
                    entry[x] for x in self.extra_labels
                ]
                gauge.add_metric(values, 1)

        logger.debug("Returning fail2ban_banned_ip gauge")
        return gauge

    def expose_grouped(self):
        gauge = GaugeMetricFamily(
            "fail2ban_location",
            "Number of currently banned IPs from this location",
            labels=self.extra_labels,
        )
        grouped = defaultdict(int)

        for jail in self.jails:
            for banned_ip in jail.ip_list:
                if not banned_ip:
                    continue
                entry = {"ip": banned_ip.ip}
                entry.update(banned_ip.extra_data)
                location_key = tuple([entry[x] for x in self.extra_labels])
                grouped[location_key] += 1

        for labels, count in grouped.items():
            gauge.add_metric(list(labels), count)

        logger.debug("Returning fail2ban_location gauge")
        return gauge

    def expose_jail_summary(self):
        gauge = GaugeMetricFamily(
            "fail2ban_jailed_ips",
            "Number of currently banned IPs per jail",
            labels=["jail"],
        )

        for jail in self.jails:
            gauge.add_metric([jail.name], len(jail.ip_list))

        logger.debug("Returning fail2ban_jailed_ips gauge")
        return gauge


def entrypoint():
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    settings = Settings()
    REGISTRY.register(F2bCollector(settings))

    app = make_wsgi_app()
    httpd = make_server(settings.server.listen_address, settings.server.port, app)
    logger.info(
        "Listening on %s:%d", settings.server.listen_address, settings.server.port
    )
    httpd.serve_forever()
    logger.info("Exiting")


if __name__ == "__main__":
    entrypoint()
