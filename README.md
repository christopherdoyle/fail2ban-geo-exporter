# fail2ban-geo-exporter

Forked from https://github.com/vdcloudcraft/fail2ban-geo-exporter with a new configuration thing and logging and some
fixes I needed to get it working with my setup.
In particular you can set configuration with environment variables.

`compose.yml`:

```yaml
services:
  exporter:
    container_name: fail2ban_exporter
    image: christopherdoyle/fail2ban-geo-exporter
    restart: always
    volumes:
      - /etc/fail2ban:/etc/fail2ban:ro
      - /var/lib/fail2ban/fail2ban.sqlite3:/var/lib/fail2ban/fail2ban.sqlite3:ro
      - ./GeoLite2-City.mmdb:/app/db/GeoLite2-City.mmdb:ro
      - ./conf.yml:/app/conf.yml:ro
```

`conf.yml`:

```yaml
server:
  listen_address: 0.0.0.0
  port: 9100
geo:
  enabled: True
  provider: "MaxmindDB"
  enable_grouping: False
  maxmind_dbpath: "/app/db/GeoLite2-City.mmdb"
fail2ban:
  conf_path: "/etc/fail2ban"
  db: "/var/lib/fail2ban/fail2ban.sqlite3"
```
