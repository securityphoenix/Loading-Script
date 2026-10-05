#!/usr/bin/env python3
"""The shared API serializer leaves publishedDateTime out when the date is blank ("", whitespace or
None), because the backend rejects the blank strings. Real dates pass through unchanged."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from phoenix_import_refactored import AssetData, PhoenixAPIClient, PhoenixConfig, VulnerabilityData

ABSENT = object()


class TestBlankPublishedDate(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)  # the client writes logs/ and errors/ into the working directory

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def published_sent(self, value):
        asset = AssetData(asset_type="INFRA", attributes={"ip": "10.0.0.1"},
                          findings=[VulnerabilityData(name="n", description="d", remedy="r", severity="5.0",
                                                      location="l", published_date_time=value)])
        response = MagicMock(status_code=200, text='{"id": "r1"}')
        response.json.return_value = {"id": "r1"}
        client = PhoenixAPIClient(PhoenixConfig(client_id="c", client_secret="s",
                                                api_base_url="https://phoenix.example.invalid"))
        with patch.object(PhoenixAPIClient, "get_access_token", return_value="t"), \
                patch("phoenix_import_refactored.requests.post", return_value=response) as post:
            client.import_assets([asset], "dates")
        return post.call_args.kwargs["json"]["assets"][0]["findings"][0].get("publishedDateTime", ABSENT)

    def test_empty_string_is_left_out(self):
        self.assertIs(self.published_sent(""), ABSENT)

    def test_whitespace_is_left_out(self):
        self.assertIs(self.published_sent("   "), ABSENT)

    def test_none_is_left_out(self):
        self.assertIs(self.published_sent(None), ABSENT)

    def test_real_date_is_unchanged(self):
        self.assertEqual(self.published_sent("2026-01-02T03:04:05Z"), "2026-01-02T03:04:05Z")


if __name__ == "__main__":
    unittest.main()
