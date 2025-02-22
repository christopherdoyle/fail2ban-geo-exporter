import configparser
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from wsgiref.simple_server import make_server

from prometheus_client import make_wsgi_app
from prometheus_client.core import REGISTRY, GaugeMetricFamily

from .config import Settings


@dataclass(slots=True)
class Jail:
    name: str
    ip_list: list[str] = field(default_factory=list)
    bantime: int = 0


class F2bCollector:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.geo_provider = self._import_provider()
        self.jails = []
        self.extra_labels = sorted(self.geo_provider.get_labels())

    def _import_provider(self):
        if self.settings.geo.enabled:
            class_name = self.settings.geo.provider
            mod = __import__(
                "geoip_provider.{}".format(class_name.lower()), fromlist=[class_name]
            )
        else:
            class_name = "BaseProvider"
            mod = __import__("geoip_provider.base", fromlist=["BaseProvider"])

        GeoProvider = getattr(mod, class_name)
        return GeoProvider(self.settings)

    def get_jailed_ips(self):
        self.jails.clear()

        conn = sqlite3.connect(self.settings.fail2ban.db_path)
        cur = conn.cursor()

        config = configparser.ConfigParser()

        config.read(f"{self.settings.fail2ban.conf_path}/jail.local")
        jaild = list((self.settings.fail2ban.conf_path / "jail.d").glob("*.local"))
        config.read(jaild)

        active_jails = cur.execute(
            "SELECT name FROM jails WHERE enabled = 1"
        ).fetchall()

        for j in active_jails:
            jail = Jail(j[0])
            bantime = config[j[0]]["bantime"].split(";")[0].strip()
            jail.bantime = int(bantime)
            self.jails.append(jail)

        for jail in self.jails:
            rows = cur.execute(
                "SELECT ip FROM bans "
                "WHERE DATETIME(timeofban + ?, 'unixepoch') > DATETIME('now') "
                "AND jail = ?",
                [jail.bantime, jail.name],
            ).fetchall()
            for row in rows:
                jail.ip_list.append({"ip": row[0]})

        conn.close()

    def assign_location(self):
        for jail in self.jails:
            for entry in jail.ip_list:
                entry.update(self.geo_provider.annotate(entry["ip"]))

    def collect(self):
        self.get_jailed_ips()
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
            for entry in jail.ip_list:
                # Skip if GeoProvider.annotate() did not return matching count of labels
                if len(entry) < len(self.extra_labels) + 1:
                    continue
                values = [jail.name, entry["ip"]] + [
                    entry[x] for x in self.extra_labels
                ]
                gauge.add_metric(values, 1)

        return gauge

    def expose_grouped(self):
        gauge = GaugeMetricFamily(
            "fail2ban_location",
            "Number of currently banned IPs from this location",
            labels=self.extra_labels,
        )
        grouped = defaultdict(int)

        for jail in self.jails:
            for entry in jail.ip_list:
                if not entry:
                    continue
                location_key = tuple([entry[x] for x in self.extra_labels])
                grouped[location_key] += 1

        for labels, count in grouped.items():
            gauge.add_metric(list(labels), count)

        return gauge

    def expose_jail_summary(self):
        gauge = GaugeMetricFamily(
            "fail2ban_jailed_ips",
            "Number of currently banned IPs per jail",
            labels=["jail"],
        )

        for jail in self.jails:
            gauge.add_metric([jail.name], len(jail.ip_list))

        return gauge


def entrypoint():
    settings = Settings()
    REGISTRY.register(F2bCollector(settings))

    app = make_wsgi_app()
    httpd = make_server(settings.server.listen_address, settings.server.port, app)
    httpd.serve_forever()


if __name__ == "__main__":
    entrypoint()
