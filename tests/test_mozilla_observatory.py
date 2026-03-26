"""Tests for Mozilla Observatory grading."""

from domain_audit.checks.mozilla_observatory import grade_observatory


class TestGradeObservatory:

    def test_no_data(self):
        result = grade_observatory(None)
        assert result["grade"] == "INFO"

    def test_a_plus(self):
        result = grade_observatory({"grade": "A+", "score": 100, "tests": {}})
        assert result["grade"] == "PASS"
        assert result["observatory_grade"] == "A+"

    def test_b_grade(self):
        result = grade_observatory({"grade": "B", "score": 70, "tests": {}})
        assert result["grade"] == "PASS"

    def test_c_grade(self):
        result = grade_observatory({"grade": "C", "score": 50, "tests": {}})
        assert result["grade"] == "WARN"

    def test_f_grade(self):
        result = grade_observatory({"grade": "F", "score": 10, "tests": {}})
        assert result["grade"] == "FAIL"

    def test_missing_grade(self):
        result = grade_observatory({"score": 50, "tests": {}})
        assert result["grade"] == "INFO"

    def test_scan_nested_format(self):
        result = grade_observatory({"scan": {"grade": "A", "score": 90}, "tests": {}})
        assert result["grade"] == "PASS"
        assert result["observatory_grade"] == "A"
