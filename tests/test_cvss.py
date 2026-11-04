import unittest

from vulntrack.cvss import base_score, roundup, severity_from_score


class BaseScoreTest(unittest.TestCase):
    # Reference scores as published by NVD / the FIRST CVSS v3.1 calculator.
    CASES = {
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 9.9,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N": 9.1,
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.6,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
    }

    def test_reference_vectors(self):
        for vector, expected in self.CASES.items():
            with self.subTest(vector=vector):
                self.assertEqual(base_score(vector).score, expected)

    def test_metric_order_does_not_matter(self):
        result = base_score("CVSS:3.1/A:N/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N")
        self.assertEqual(result.score, 9.1)
        self.assertEqual(result.vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
        self.assertEqual(result.severity, "critical")

    def test_temporal_metrics_are_ignored(self):
        self.assertEqual(base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O").score, 9.8)

    def test_invalid_vectors(self):
        for vector in (
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
            "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ):
            with self.subTest(vector=vector), self.assertRaises(ValueError):
                base_score(vector)

    def test_roundup(self):
        self.assertEqual(roundup(4.02), 4.1)
        self.assertEqual(roundup(4.0), 4.0)
        self.assertEqual(roundup(4.000000000001), 4.0)

    def test_severity_bands(self):
        self.assertEqual(severity_from_score(0.0), "info")
        self.assertEqual(severity_from_score(0.1), "low")
        self.assertEqual(severity_from_score(3.9), "low")
        self.assertEqual(severity_from_score(4.0), "medium")
        self.assertEqual(severity_from_score(7.0), "high")
        self.assertEqual(severity_from_score(9.0), "critical")


if __name__ == "__main__":
    unittest.main()
