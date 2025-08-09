import logging

import geoip2.database

from .base import BaseProvider

logger = logging.getLogger(__name__)


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
        except Exception:
            logger.error("Failed to retrieve location for ip '%s'", ip)
            return None
        finally:
            reader.close()
        return entry

    def get_labels(self):
        return ["city", "latitude", "longitude"]
