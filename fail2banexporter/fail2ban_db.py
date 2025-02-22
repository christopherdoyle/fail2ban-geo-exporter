import pathlib
import sqlite3


class Fail2BanDatabaseInterface:

    def __init__(self, fpath: pathlib.Path):
        self.fpath = fpath
        if not self.fpath.is_file():
            raise ValueError("Database file does not exist")

        self.conn = sqlite3.connect(self.fpath)
        self.cur = self.conn.cursor()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def __del__(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def fetch_active_jails(self) -> list[str]:
        results = self.cur.execute(
            "SELECT name FROM jails WHERE enabled = 1"
        ).fetchall()
        return [r[0] for r in results]

    def fetch_banned_ips(
        self, jail_name: str, last_n_minutes: int | None = None
    ) -> list[str]:
        sql = "SELECT ip FROM bans WHERE jail = ?"
        params = [jail_name]
        if last_n_minutes is not None:
            sql += " AND DATETIME(timeofban + ?, 'unixepoch') > DATETIME('now') "
            params.append(last_n_minutes)
        result = self.cur.execute(sql, params).fetchall()
        return [r[0] for r in result]
