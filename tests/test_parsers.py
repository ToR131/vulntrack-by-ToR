import unittest
from pathlib import Path

from vulntrack.parsers import decode, detect, load
from vulntrack.parsers._common import normalize_url, query_params, strip_html

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def by_rule(result, prefix):
    return next(f for f in result.findings if f.rule_id.startswith(prefix))


class ZapTest(unittest.TestCase):
    result = load(SAMPLES / "zap_report.json")

    def test_one_finding_per_instance_without_false_positives(self):
        self.assertEqual(self.result.tool, "zap")
        self.assertEqual(len(self.result.findings), 7)
        self.assertFalse(any(f.rule_id == "10021" for f in self.result.findings))

    def test_sql_injection(self):
        sqli = by_rule(self.result, "40018")
        self.assertEqual(sqli.severity, "high")
        self.assertEqual(sqli.cwe, "89")
        self.assertEqual(sqli.weakness, "CWE-89")
        self.assertEqual(sqli.location, "https://shop.example.test/api/products")
        self.assertEqual(sqli.params, ["id"])
        self.assertEqual(sqli.asset, "shop.example.test")
        self.assertNotIn("<p>", sqli.remediation)
        self.assertIn("cheatsheetseries.owasp.org", sqli.references[0])

    def test_generic_cwe_stays_per_rule(self):
        csp = by_rule(self.result, "10038")
        self.assertEqual(csp.weakness, "zap:10038")

    def test_object_ids_collapse(self):
        csrf = by_rule(self.result, "10202")
        self.assertEqual(csrf.location, "https://shop.example.test/profile/{id}/edit")


class NucleiTest(unittest.TestCase):
    result = load(SAMPLES / "nuclei_results.jsonl")

    def test_parses_jsonl(self):
        self.assertEqual(self.result.tool, "nuclei")
        self.assertEqual(len(self.result.findings), 4)

    def test_cve_classification(self):
        cve = by_rule(self.result, "CVE-2021-41773")
        self.assertEqual(cve.cve, "CVE-2021-41773")
        self.assertEqual(cve.cwe, "22")
        self.assertEqual(cve.weakness, "CVE-2021-41773")
        self.assertEqual(cve.cvss_vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        self.assertIn("--path-as-is", cve.evidence)

    def test_sqli_matches_zap_endpoint(self):
        sqli = by_rule(self.result, "sqli-error-based")
        self.assertEqual(sqli.weakness, "CWE-89")
        self.assertEqual(sqli.location, "https://shop.example.test/api/products")
        self.assertEqual(sqli.params, ["id"])

    def test_matcher_name_splits_findings(self):
        headers = by_rule(self.result, "http-missing-security-headers")
        self.assertEqual(headers.rule_id, "http-missing-security-headers:x-frame-options")
        self.assertEqual(headers.severity, "info")

    def test_json_array_export(self):
        self.assertEqual(detect(decode('[{"template-id": "x", "info": {}}]')), "nuclei")


class SarifTest(unittest.TestCase):
    result = load(SAMPLES / "semgrep.sarif")

    def test_tool_and_count(self):
        self.assertEqual(self.result.tool, "semgrep-oss")
        self.assertEqual(len(self.result.findings), 3)

    def test_sql_injection_in_code(self):
        sqli = by_rule(self.result, "python.lang.security.audit.formatted-sql-query")
        self.assertEqual(sqli.cwe, "89")
        self.assertEqual(sqli.location, "app/db.py:27")
        self.assertEqual(sqli.severity, "high")
        self.assertIn("cursor.execute(f", sqli.evidence)
        self.assertIsNone(sqli.asset)

    def test_security_severity_overrides_level(self):
        self.assertEqual(by_rule(self.result, "generic.secrets").severity, "high")
        self.assertEqual(by_rule(self.result, "python.flask").severity, "medium")


class DetectTest(unittest.TestCase):
    def test_unknown_format(self):
        with self.assertRaises(ValueError):
            detect({"foo": "bar"})

    def test_empty_report(self):
        with self.assertRaises(ValueError):
            decode("   ")


class HelpersTest(unittest.TestCase):
    def test_normalize_url(self):
        self.assertEqual(normalize_url("HTTPS://Shop.Example.TEST:443/Users/42/?x=1#top"),
                         "https://shop.example.test/Users/{id}")
        self.assertEqual(normalize_url("http://host:8080/a/3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90"),
                         "http://host:8080/a/{id}")
        self.assertEqual(normalize_url("https://host"), "https://host/")
        self.assertEqual(normalize_url("host:22"), "host:22")

    def test_query_params(self):
        self.assertEqual(query_params("https://h/p?b=1&a=&b=2"), ["a", "b"])

    def test_strip_html(self):
        self.assertEqual(strip_html("<p>One &amp; two.</p><p>Three</p>"), "One & two.\nThree")


if __name__ == "__main__":
    unittest.main()
