import geoip2.database

from .base import BaseProvider


class MaxmindDB(BaseProvider):

    def annotate(self, ip):
        reader = geoip2.database.Reader(self.settings.geo.maxmind_dbpath)
        try:
            lookup = reader.city(ip)
            entry = {
                "city": str(lookup.city.name),
                "latitude": str(lookup.location.latitude),
                "longitude": str(lookup.location.longitude),
            }
        finally:
            reader.close()
        return entry

    def get_labels(self):
        return ["city", "latitude", "longitude"]
