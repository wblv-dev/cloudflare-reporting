"""Tests for reporter helper functions and CSV output."""

import csv
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from lib.reporter import _worst, _sym, _truncate, _badge, write_csv, GRADE_SYMBOL


class TestWorst:

    def test_single(self):
        assert _worst(["PASS"]) == "PASS"

    def test_fail_wins(self):
        assert _worst(["PASS", "WARN", "FAIL"]) == "FAIL"

    def test_warn_beats_pass(self):
        assert _worst(["PASS", "WARN"]) == "WARN"


class TestSym:

    def test_known_grades(self):
        for grade in ("PASS", "WARN", "FAIL", "INFO"):
            assert grade in _sym(grade)

    def test_unknown_grade(self):
        assert _sym("UNKNOWN") == "UNKNOWN"


class TestTruncate:

    def test_short_string(self):
        assert _truncate("hello", 80) == "hello"

    def test_long_string(self):
        result = _truncate("a" * 100, 20)
        assert len(result) == 20
        assert result.endswith("...")


class TestBadge:

    def test_pass_badge(self):
        html = _badge("PASS")
        assert "badge-success" in html
        assert "PASS" in html

    def test_custom_text(self):
        html = _badge("FAIL", "Critical")
        assert "Critical" in html
        assert "badge-danger" in html


class TestWriteCsv:

    def _sample_data(self):
        return {
            "domains": ["example.com"],
            "dns_results": {"example.com": {"total": 10, "by_type": {"A": 3}, "proxied": 2, "records": []}},
            "email_results": {"example.com": {
                "spf": {"grade": "PASS", "reason": "ok", "record": "v=spf1 -all"},
                "dmarc": {"grade": "PASS", "reason": "ok", "record": "v=DMARC1; p=reject", "policy": "reject", "rua": None},
                "dkim": [{"selector": "google", "record": "v=DKIM1; k=rsa; p=..."}],
                "mx": [], "has_mail": False,
            }},
            "security_results": {"example.com": {
                "results": [{"grade": "PASS"}, {"grade": "WARN"}],
                "score": (1, 2),
            }},
            "registrar_results": {"example.com": {
                "registrar": "Cloudflare",
                "expiry": {"grade": "PASS", "days_remaining": 300},
                "lock": {"grade": "PASS"},
            }},
            "dns_sec_results": {"example.com": {
                "dnssec": {"grade": "PASS"},
                "caa": {"grade": "WARN"},
                "dangling": {"grade": "PASS", "dangling": []},
            }},
            "blacklist_results": {"example.com": {"grade": "PASS"}},
            "rdns_results": {"example.com": {"grade": "INFO"}},
        }

    def test_writes_csv_file(self):
        fd, path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        try:
            data = self._sample_data()
            write_csv(output_path=path, **data)

            with open(path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            assert len(rows) == 1
            row = rows[0]
            assert row["Domain"] == "example.com"
            assert row["SPF"] == "PASS"
            assert row["DMARC"] == "PASS"
            assert row["DKIM Selectors"] == "1"
            assert row["Zone Pass"] == "1"
            assert row["Zone Total"] == "2"
            assert row["Registrar"] == "Cloudflare"
            assert row["Expiry"] == "PASS"
            assert row["DNSSEC"] == "PASS"
            assert row["CAA"] == "WARN"
            assert row["Blacklist"] == "PASS"
            assert row["Reverse DNS"] == "INFO"
        finally:
            os.unlink(path)

    def test_multiple_domains(self):
        fd, path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        try:
            data = self._sample_data()
            data["domains"] = ["a.com", "b.com"]
            data["dns_results"] = {
                "a.com": {"total": 5, "by_type": {}, "proxied": 0, "records": []},
                "b.com": {"total": 3, "by_type": {}, "proxied": 0, "records": []},
            }
            # Minimal data for other results
            for d in ["a.com", "b.com"]:
                data["email_results"][d] = data["email_results"].pop("example.com", {
                    "spf": {"grade": "PASS"}, "dmarc": {"grade": "PASS"}, "dkim": [],
                    "mx": [], "has_mail": False,
                })
                data["security_results"][d] = {"results": [{"grade": "PASS"}], "score": (1, 1)}
                data["registrar_results"][d] = {"registrar": "", "expiry": {"grade": "PASS"}, "lock": {"grade": "PASS"}}
                data["dns_sec_results"][d] = {"dnssec": {"grade": "PASS"}, "caa": {"grade": "PASS"}, "dangling": {"grade": "PASS", "dangling": []}}
                data["blacklist_results"][d] = {"grade": "PASS"}
                data["rdns_results"][d] = {"grade": "PASS"}

            write_csv(output_path=path, **data)

            with open(path, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            assert len(rows) == 2
            assert rows[0]["Domain"] == "a.com"
            assert rows[1]["Domain"] == "b.com"
        finally:
            os.unlink(path)
