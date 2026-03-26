"""Tests for Shodan InternetDB grading."""

from domain_audit.checks.shodan_internetdb import grade_internetdb


class TestGradeInternetdb:

    def test_no_data(self):
        result = grade_internetdb([])
        assert result["grade"] == "INFO"

    def test_clean_ports(self):
        result = grade_internetdb([{"data": {"ports": [80, 443], "vulns": [], "tags": []}}])
        assert result["grade"] == "PASS"

    def test_risky_port(self):
        result = grade_internetdb([{"data": {"ports": [80, 443, 3389], "vulns": [], "tags": []}}])
        assert result["grade"] == "WARN"
        assert "3389" in result["reason"]

    def test_vulns_found(self):
        result = grade_internetdb([{"data": {"ports": [80], "vulns": ["CVE-2024-1234"], "tags": []}}])
        assert result["grade"] == "FAIL"
        assert "CVE" in result["reason"]

    def test_no_data_entry(self):
        result = grade_internetdb([{"data": None}])
        assert result["grade"] == "INFO"
