"""Tests for web_security grading logic."""

from domain_audit.checks.web_security import grade_header, grade_security_txt, SECURITY_HEADERS


class TestGradeHeader:

    def _check(self, name):
        return next(c for c in SECURITY_HEADERS if c["header"] == name)

    def test_missing_header(self):
        result = grade_header(self._check("x-frame-options"), None)
        assert result["grade"] == "FAIL"
        assert result["actual"] == "Missing"

    def test_xfo_deny(self):
        result = grade_header(self._check("x-frame-options"), "DENY")
        assert result["grade"] == "PASS"

    def test_xfo_sameorigin(self):
        result = grade_header(self._check("x-frame-options"), "SAMEORIGIN")
        assert result["grade"] == "PASS"

    def test_csp_present(self):
        result = grade_header(self._check("content-security-policy"), "default-src 'self'")
        assert result["grade"] == "PASS"

    def test_xcto_nosniff(self):
        result = grade_header(self._check("x-content-type-options"), "nosniff")
        assert result["grade"] == "PASS"

    def test_referrer_strict(self):
        result = grade_header(self._check("referrer-policy"), "strict-origin-when-cross-origin")
        assert result["grade"] == "PASS"

    def test_referrer_unsafe(self):
        result = grade_header(self._check("referrer-policy"), "unsafe-url")
        assert result["grade"] == "WARN"

    def test_hsts_good(self):
        result = grade_header(self._check("strict-transport-security"), "max-age=31536000; includeSubDomains")
        assert result["grade"] == "PASS"

    def test_hsts_low_max_age(self):
        result = grade_header(self._check("strict-transport-security"), "max-age=3600")
        assert result["grade"] == "WARN"


class TestGradeSecurityTxt:

    def test_not_found(self):
        result = grade_security_txt(None)
        assert result["grade"] == "WARN"

    def test_valid_with_contact(self):
        result = grade_security_txt("Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z")
        assert result["grade"] == "PASS"

    def test_missing_expires(self):
        result = grade_security_txt("Contact: mailto:security@example.com")
        assert result["grade"] == "WARN"
        assert "Expires" in result["reason"]

    def test_missing_contact(self):
        result = grade_security_txt("Expires: 2027-01-01T00:00:00Z")
        assert result["grade"] == "WARN"
        assert "Contact" in result["reason"]
