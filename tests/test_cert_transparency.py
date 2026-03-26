"""Tests for cert_transparency grading and parsing."""

from domain_audit.checks.cert_transparency import _parse_certs, grade_ct


class TestParseCerts:

    def test_empty(self):
        result = _parse_certs([], "example.com")
        assert result["total_certs"] == 0
        assert result["unique_subdomains"] == []

    def test_basic_cert(self):
        raw = [{
            "common_name": "example.com",
            "issuer_name": "O=Let's Encrypt",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2026-04-01T00:00:00",
            "name_value": "example.com\nwww.example.com",
        }]
        result = _parse_certs(raw, "example.com")
        assert result["total_certs"] == 1
        assert "example.com" in result["unique_subdomains"]
        assert "www.example.com" in result["unique_subdomains"]
        assert "Let's Encrypt" in result["issuers"]

    def test_wildcard_counted(self):
        raw = [{
            "common_name": "*.example.com",
            "issuer_name": "O=DigiCert",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2027-01-01T00:00:00",
            "name_value": "*.example.com",
        }]
        result = _parse_certs(raw, "example.com")
        assert result["wildcard_certs"] == 1

    def test_deduplication(self):
        entry = {
            "common_name": "example.com",
            "issuer_name": "O=Let's Encrypt",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2026-04-01T00:00:00",
            "name_value": "example.com",
        }
        result = _parse_certs([entry, entry, entry], "example.com")
        assert result["total_certs"] == 1


class TestGradeCt:

    def test_no_data(self):
        parsed = _parse_certs([], "example.com")
        result = grade_ct(parsed)
        assert result["grade"] == "INFO"

    def test_normal(self):
        parsed = {
            "total_certs": 5,
            "unique_subdomains": ["a.example.com", "b.example.com"],
            "issuers": {"Let's Encrypt": 5},
            "wildcard_certs": 0,
        }
        result = grade_ct(parsed)
        assert result["grade"] == "PASS"

    def test_many_wildcards(self):
        parsed = {
            "total_certs": 10,
            "unique_subdomains": ["a.example.com"],
            "issuers": {"DigiCert": 10},
            "wildcard_certs": 5,
        }
        result = grade_ct(parsed)
        assert result["grade"] == "WARN"
