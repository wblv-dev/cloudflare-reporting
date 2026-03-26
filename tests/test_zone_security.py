"""Tests for zone_security grading functions and bulk settings extraction."""

from domain_audit.checks.zone_security import (
    _grade, _grade_hsts, _extract_setting, _extract_hsts, CHECKS,
)


class TestGrade:

    def _check(self, setting_name):
        return next(c for c in CHECKS if c["setting"] == setting_name)

    def test_ssl_full_strict_passes(self):
        result = _grade(self._check("ssl"), "strict")
        assert result["grade"] == "PASS"

    def test_ssl_full_passes(self):
        result = _grade(self._check("ssl"), "full")
        assert result["grade"] == "PASS"

    def test_ssl_flexible_warns(self):
        result = _grade(self._check("ssl"), "flexible")
        assert result["grade"] == "WARN"

    def test_ssl_off_fails(self):
        result = _grade(self._check("ssl"), "off")
        assert result["grade"] == "FAIL"

    def test_unavailable_setting(self):
        result = _grade(self._check("ssl"), None)
        assert result["grade"] == "INFO"

    def test_min_tls_12_passes(self):
        result = _grade(self._check("min_tls_version"), "1.2")
        assert result["grade"] == "PASS"

    def test_min_tls_10_fails(self):
        result = _grade(self._check("min_tls_version"), "1.0")
        assert result["grade"] == "FAIL"

    def test_tls_13_on_passes(self):
        result = _grade(self._check("tls_1_3"), "on")
        assert result["grade"] == "PASS"

    def test_always_https_off_fails(self):
        result = _grade(self._check("always_use_https"), "off")
        assert result["grade"] == "FAIL"

    # ── New checks ───────────────────────────────────────────────────────────

    def test_security_level_medium_passes(self):
        result = _grade(self._check("security_level"), "medium")
        assert result["grade"] == "PASS"

    def test_security_level_high_passes(self):
        result = _grade(self._check("security_level"), "high")
        assert result["grade"] == "PASS"

    def test_security_level_under_attack_passes(self):
        result = _grade(self._check("security_level"), "under_attack")
        assert result["grade"] == "PASS"

    def test_security_level_low_warns(self):
        result = _grade(self._check("security_level"), "low")
        assert result["grade"] == "WARN"

    def test_security_level_off_fails(self):
        result = _grade(self._check("security_level"), "essentially_off")
        assert result["grade"] == "FAIL"

    def test_browser_check_on_passes(self):
        result = _grade(self._check("browser_check"), "on")
        assert result["grade"] == "PASS"

    def test_browser_check_off_fails(self):
        result = _grade(self._check("browser_check"), "off")
        assert result["grade"] == "FAIL"

    def test_email_obfuscation_on_passes(self):
        result = _grade(self._check("email_obfuscation"), "on")
        assert result["grade"] == "PASS"

    def test_email_obfuscation_off_fails(self):
        result = _grade(self._check("email_obfuscation"), "off")
        assert result["grade"] == "FAIL"

    def test_hotlink_protection_on_passes(self):
        result = _grade(self._check("hotlink_protection"), "on")
        assert result["grade"] == "PASS"

    def test_hotlink_protection_off_fails(self):
        result = _grade(self._check("hotlink_protection"), "off")
        assert result["grade"] == "FAIL"


class TestGradeHsts:

    def test_disabled(self):
        result = _grade_hsts({"enabled": False, "max_age": 0,
                              "include_subdomains": False, "preload": False})
        assert result["grade"] == "WARN"

    def test_enabled_high_max_age(self):
        result = _grade_hsts({"enabled": True, "max_age": 31536000,
                              "include_subdomains": True, "preload": True})
        assert result["grade"] == "PASS"
        assert "preload" in result["note"]

    def test_enabled_low_max_age(self):
        result = _grade_hsts({"enabled": True, "max_age": 3600,
                              "include_subdomains": False, "preload": False})
        assert result["grade"] == "WARN"

    def test_unavailable(self):
        result = _grade_hsts({"enabled": None, "max_age": None,
                              "include_subdomains": None, "preload": None})
        assert result["grade"] == "INFO"


class TestExtractSetting:

    def test_present(self):
        settings = {"ssl": "full", "tls_1_3": "on"}
        assert _extract_setting(settings, "ssl") == "full"

    def test_missing(self):
        assert _extract_setting({}, "ssl") is None

    def test_normalises_case(self):
        settings = {"ssl": "FULL"}
        assert _extract_setting(settings, "ssl") == "full"

    def test_normalises_whitespace(self):
        settings = {"ssl": " strict "}
        assert _extract_setting(settings, "ssl") == "strict"


class TestExtractHsts:

    def test_present(self):
        settings = {
            "security_header": {
                "strict_transport_security": {
                    "enabled": True,
                    "max_age": 31536000,
                    "include_subdomains": True,
                    "preload": True,
                }
            }
        }
        hsts = _extract_hsts(settings)
        assert hsts["enabled"] is True
        assert hsts["max_age"] == 31536000
        assert hsts["preload"] is True

    def test_missing(self):
        hsts = _extract_hsts({})
        assert hsts["enabled"] is None

    def test_not_dict(self):
        hsts = _extract_hsts({"security_header": "unexpected"})
        assert hsts["enabled"] is None
