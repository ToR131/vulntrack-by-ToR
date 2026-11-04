import csv
import io
import unittest
from datetime import date
from pathlib import Path

from vulntrack.models import Finding, ParseResult
from vulntrack.parsers import load
from vulntrack.report import render_csv, render_html, render_markdown
from vulntrack.store import connect, import_report

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
TODAY = date(2026, 11, 2)


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        for name in ("zap_report.json", "nuclei_results.jsonl", "semgrep.sarif"):
            import_report(self.conn, load(SAMPLES / name), TODAY, asset="demo-shop")

    def tearDown(self):
        self.conn.close()

    def add(self, **overrides):
        values = dict(tool="manual", rule_id="r1", title="Test", severity="high", location="https://evil.test/")
        values.update(overrides)
        import_report(self.conn, ParseResult("manual", [Finding(**values)]), TODAY, asset="demo-shop")

    def test_html_escapes_scanner_payloads(self):
        html = render_html(self.conn, TODAY)
        self.assertNotIn("<script>alert(1);</script>", html)
        self.assertIn("&lt;script&gt;alert(1);&lt;/script&gt;", html)

    def test_html_links_only_http(self):
        self.add(references=["javascript:alert(document.cookie)", "https://ok.example/advisory"])
        html = render_html(self.conn, TODAY)
        self.assertNotIn('href="javascript:', html)
        self.assertIn('href="https://ok.example/advisory"', html)

    def test_html_hides_info_by_default(self):
        self.assertNotIn("x-frame-options", render_html(self.conn, TODAY))
        self.assertIn("x-frame-options", render_html(self.conn, TODAY, include_info=True))

    def test_markdown_table(self):
        md = render_markdown(self.conn, TODAY, asset="demo-shop")
        self.assertIn("| ID | Критичность |", md)
        self.assertIn("CVE-2021-41773", md)

    def test_csv_neutralizes_formulas(self):
        self.add(title='=HYPERLINK("https://evil.test","click")')
        rows = list(csv.DictReader(io.StringIO(render_csv(self.conn, TODAY))))
        self.assertEqual(len(rows), 14)
        titles = [r["title"] for r in rows]
        self.assertIn('\'=HYPERLINK("https://evil.test","click")', titles)


if __name__ == "__main__":
    unittest.main()
