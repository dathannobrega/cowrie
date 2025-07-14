from __future__ import annotations

import re
import socket
from datetime import datetime
from twisted.internet import task

import cowrie.core.output
from cowrie.core.config import CowrieConfig

try:
    import mysql.connector
except Exception:  # pragma: no cover - optional dependency
    mysql = None

class Output(cowrie.core.output.Output):
    """Output plugin that stores and checks URLs seen in Cowrie events."""

    def start(self):
        host = CowrieConfig.get("output_mysql", "host")
        database = CowrieConfig.get("output_mysql", "database")
        username = CowrieConfig.get("output_mysql", "username")
        password = CowrieConfig.get("output_mysql", "password", raw=True)
        port = CowrieConfig.getint("output_mysql", "port", fallback=3306)

        self.conn = mysql.connector.connect(
            host=host, database=database, user=username, password=password, port=port
        )
        self.cursor = self.conn.cursor()
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS urls (
                id INT AUTO_INCREMENT PRIMARY KEY,
                url TEXT NOT NULL,
                first_view DATETIME NULL,
                last_view DATETIME NULL
            )
            """
        )
        self.conn.commit()
        self.known_urls: set[str] = set(
            row[0] for row in self._fetchall("SELECT url FROM urls")
        )

        self.verify_interval = CowrieConfig.getint(
            "output_urlsniffer", "verify_interval", fallback=300
        )
        self._lc = task.LoopingCall(self._verify_existing_urls)
        self._lc.start(self.verify_interval, now=False)

    def stop(self):
        if hasattr(self, "_lc") and self._lc.running:
            self._lc.stop()
        if self.conn.is_connected():
            self.cursor.close()
            self.conn.close()

    def _fetchall(self, query: str, params: tuple | None = None):
        self.cursor.execute(query, params or ())
        return self.cursor.fetchall()

    def _execute(self, query: str, params: tuple):
        self.cursor.execute(query, params)
        self.conn.commit()

    def write(self, event: dict):
        urls = set()
        if event["eventid"] == "cowrie.session.file_download":
            url = event.get("url")
            if url:
                urls.add(url)
        elif event["eventid"] == "cowrie.command.input":
            urls |= self._extract_urls(event.get("input", ""))

        for url in urls:
            self._insert_or_update(url)

    def _extract_urls(self, text: str) -> set[str]:
        pattern = r"https?://[^\s<>\"]+|www\.[^\s<>\"]+"
        return {u.rstrip(";") for u in re.findall(pattern, text)}

    def _insert_or_update(self, url: str) -> None:
        now = datetime.utcnow()
        if url not in self.known_urls:
            self._execute(
                "INSERT INTO urls (url, first_view, last_view) VALUES (%s, %s, %s)",
                (url, now, now),
            )
            self.known_urls.add(url)
        else:
            self._execute(
                "UPDATE urls SET last_view=%s WHERE url=%s", (now, url)
            )
        if self._check_connectivity(url):
            self._execute("UPDATE urls SET last_view=%s WHERE url=%s", (now, url))

    def _verify_existing_urls(self) -> None:
        now = datetime.utcnow()
        for (url,) in self._fetchall("SELECT url FROM urls"):
            if self._check_connectivity(url):
                self._execute(
                    "UPDATE urls SET last_view=%s WHERE url=%s",
                    (now, url),
                )

    def _check_connectivity(self, url: str) -> bool:
        pattern = r"https?://((?:\d{1,3}\.){3}\d{1,3}|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?::(\d+))?"
        m = re.search(pattern, url)
        if not m:
            return False
        host = m.group(1)
        port = int(m.group(2)) if m.group(2) else (443 if url.startswith("https") else 80)
        try:
            with socket.create_connection((host, port), timeout=5):
                return True
        except OSError:
            return False
