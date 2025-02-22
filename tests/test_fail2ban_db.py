import sqlite3

import pytest

from fail2banexporter import fail2ban_db


@pytest.fixture(scope="session")
def _mock_fail2ban_sqlite_db(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("db") / "fail2ban.sqlite3"

    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    # just the tables we need to test
    cursor.execute(
        """
        CREATE TABLE jails (
            name TEXT NOT NULL UNIQUE,
            enabled INTEGER NOT NULL DEFAULT 1
        );"""
    )
    cursor.execute(
        """
        CREATE TABLE bans (
            jail TEXT NOT NULL,
            ip TEXT,
            timeofban INTEGER NOT NULL,
            bantime INTEGER NOT NULL,
            bancount INTEGER NOT NULL default 1,
            data JSON,
            FOREIGN KEY(jail) REFERENCES jails(name)
        );"""
    )
    yield db_path


@pytest.fixture(scope="function")
def mock_fail2ban_sqlite_db(_mock_fail2ban_sqlite_db):
    conn = sqlite3.connect(str(_mock_fail2ban_sqlite_db))
    cursor = conn.cursor()
    cursor.execute("DELETE FROM bans")
    cursor.execute("DELETE FROM jails")
    conn.close()
    yield _mock_fail2ban_sqlite_db


class TestFail2BanDatabaseInterface:

    def test_empty_db_is_empty(self, mock_fail2ban_sqlite_db):
        db = fail2ban_db.Fail2BanDatabaseInterface(mock_fail2ban_sqlite_db)
        assert db.fetch_active_jails() == []
        assert db.fetch_banned_ips("sshd") == []

    def test_fetch_active_jails(self, mock_fail2ban_sqlite_db):
        with sqlite3.connect(mock_fail2ban_sqlite_db) as conn:
            cursor = conn.cursor()
            cursor.executemany(
                "INSERT INTO jails VALUES (?, ?)",
                [("sshd", 1), ("other", 0), ("bob", 1)],
            )

        db = fail2ban_db.Fail2BanDatabaseInterface(mock_fail2ban_sqlite_db)
        assert db.fetch_active_jails() == ["sshd", "bob"]
