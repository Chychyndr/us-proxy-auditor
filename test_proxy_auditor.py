"""Offline tests: uv run python -m unittest -v test_proxy_auditor.py"""
import argparse
import csv
import json
import tempfile
import unittest
from pathlib import Path

from us_proxy_auditor import (
    Proxy, Result, csv_row, final_status, org_type, parse_proxy, parse_source,
    rank, write_results,
)


class ProxyAuditorTests(unittest.TestCase):
    def test_parses_proxy_protocols(self):
        self.assertEqual(parse_proxy("8.8.8.8:1080", "socks5"), ("socks5", "8.8.8.8", 1080))
        self.assertEqual(parse_proxy("socks5h://1.1.1.1:9000", "http"), ("socks5", "1.1.1.1", 9000))
        self.assertEqual(parse_proxy("http://9.9.9.9:3128", "socks5"), ("http", "9.9.9.9", 3128))

    def test_rejects_bad_or_private_proxy(self):
        for value in (
            "127.0.0.1:80", "10.0.0.1:8080", "192.168.1.1:3128", "0.0.0.0:1080",
            "169.254.1.1:3128", "localhost:8080", "8.8.8.8:0", "8.8.8.8:70000",
            "https://8.8.8.8:443", "http://user:pass@8.8.8.8:443", "garbage", "# comment",
        ):
            with self.subTest(value=value):
                self.assertIsNone(parse_proxy(value, "http"))

    def test_source_dedup_and_hints(self):
        data = {}
        self.assertEqual(parse_source("8.8.8.8:1080\n1.1.1.1:1080", "socks5", "a", False, data), 2)
        self.assertEqual(parse_source("8.8.8.8:1080\n", "socks5", "b", True, data), 0)
        self.assertEqual(len(data), 2)
        self.assertTrue(data["socks5://8.8.8.8:1080"].us_hint)
        self.assertEqual(len(data["socks5://8.8.8.8:1080"].origins), 2)

    def test_strict_geolocation(self):
        p = Proxy("http", "8.8.8.8", 8080)
        args = argparse.Namespace(exclude_hosting=False, check_google=False, check_headers=False)
        r = Result(proxy=p, status="pending_geo", country_1="US", country_2="US")
        self.assertEqual(final_status(r, args), "verified_us")
        r.country_2 = "DE"
        self.assertEqual(final_status(r, args), "unconfirmed_us")
        r.country_1 = "DE"
        self.assertEqual(final_status(r, args), "not_us")
        r.country_1 = ""
        r.country_2 = ""
        self.assertEqual(final_status(r, args), "geo_unavailable")
        r.country_1 = "US"
        r.country_2 = "US"
        args.check_google = True
        r.site_http_status = "403"
        self.assertEqual(final_status(r, args), "google_not_confirmed")
        r.site_http_status = "204"
        args.check_headers = True
        r.headers_leak = "present"
        self.assertEqual(final_status(r, args), "forwarding_headers")

    def test_isp_heuristics(self):
        self.assertEqual(org_type("Comcast Cable"), "possibly_isp")
        self.assertEqual(org_type("AWS Amazon.com"), "possibly_hosting")
        self.assertEqual(org_type("Random ISP"), "unknown")

    def test_csv_and_json_generation(self):
        p = Proxy("socks5", "8.8.8.8", 1080, origins={"a"}, us_hint=True)
        r = Result(proxy=p, status="verified_us", exit_ip="8.8.8.8",
                   country_1="US", country_2="US", latency_ms=123, successes=3, attempts=3)
        args = argparse.Namespace(rounds=3, timeout=7, concurrency=30, limit=50, geo_cap=30,
                                  check_google=False, check_headers=False, exclude_hosting=False)
        with tempfile.TemporaryDirectory() as d:
            write_results([r], Path(d), {"a": {"new_candidates": 1}}, args)
            self.assertIn("socks5://8.8.8.8:1080", (Path(d) / "verified_us.txt").read_text())
            with (Path(d) / "verified_us.csv").open(encoding="utf-8-sig", newline="") as file:
                self.assertEqual(next(csv.DictReader(file))["status"], "verified_us")
            self.assertEqual(json.loads((Path(d) / "report.json").read_text())["verified_us"], 1)


if __name__ == "__main__":
    unittest.main()
