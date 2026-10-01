#!/usr/bin/env python3
"""phoenix-scanner-client must not allow older versions than the scanner service of the HTTP and
ASN.1 libraries they both pin for security fixes (requests, urllib3, aiohttp, pyasn1)."""

import re
import sys
import unittest
from pathlib import Path

from packaging.version import Version

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SECURITY_PINNED = ("requests", "urllib3", "aiohttp", "pyasn1")
_MINIMUM = re.compile(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*>=\s*([0-9][^,;\s#]*)")


def minimums(path: Path) -> dict:
    found = {}
    for line in path.read_text().splitlines():
        match = _MINIMUM.match(line.strip())
        if match:
            found[match.group(1).lower()] = Version(match.group(2))
    return found


class TestClientDependencyFloors(unittest.TestCase):
    def test_client_floors_are_not_below_the_service(self):
        client = minimums(ROOT / "phoenix-scanner-client" / "requirements.txt")
        service = minimums(ROOT / "phoenix-scanner-service" / "requirements.txt")
        for package in SECURITY_PINNED:
            with self.subTest(package=package):
                self.assertIn(package, service)
                self.assertIn(package, client, f"{package} has no minimum in the client requirements")
                self.assertGreaterEqual(client[package], service[package])


if __name__ == "__main__":
    unittest.main()
