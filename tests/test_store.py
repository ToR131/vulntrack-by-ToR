import unittest
from datetime import date, timedelta
from pathlib import Path

from vulntrack.parsers import load
from vulntrack.store import (
    FindingNotFound,
    connect,
    events_for,
    import_report,
    list_findings,
    summary,
    update_finding,
)

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
TODAY = date(2026, 11, 2)
XSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")

    def tearDown(self):
        self.conn.close()

    def ingest(self, name, today=TODAY, **kwargs):
        return import_report(self.conn, load(SAMPLES / name), today, asset="demo-shop", **kwargs)

    def find(self, weakness, location_suffix=""):
        return self.conn.execute(
            "SELECT * FROM findings WHERE weakness = ? AND location LIKE ?", (weakness, f"%{location_suffix}")
        ).fetchone()

    def count(self):
        return self.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

    def test_first_import_of_three_scanners(self):
        self.assertEqual(self.ingest("zap_report.json").new, 7)
        nuclei = self.ingest("nuclei_results.jsonl")
        self.assertEqual((nuclei.new, nuclei.correlated), (3, 1))
        self.assertEqual(self.ingest("semgrep.sarif").new, 3)
        self.assertEqual(self.count(), 13)

    def test_same_issue_from_two_scanners_is_one_finding(self):
        self.ingest("zap_report.json")
        self.ingest("nuclei_results.jsonl")
        sqli = self.find("CWE-89", "/api/products")
        self.assertEqual(sqli["tools"], "nuclei,zap")
        self.assertEqual(sqli["severity"], "critical")  # nuclei rates it higher than ZAP
        self.assertEqual(sqli["due_date"], (TODAY + timedelta(days=7)).isoformat())
        self.assertIn("— nuclei:", sqli["evidence"])
        self.assertTrue(sqli["evidence"].startswith("— zap:"))

    def test_reimport_is_idempotent(self):
        self.ingest("zap_report.json")
        again = self.ingest("zap_report.json", TODAY + timedelta(days=1))
        self.assertEqual((again.new, again.known), (0, 7))
        self.assertEqual(self.count(), 7)

    def test_rescan_closes_fixed_and_detects_regressions(self):
        self.ingest("zap_report.json")
        self.ingest("nuclei_results.jsonl")
        rescan = self.ingest("zap_report_rescan.json", TODAY + timedelta(days=10), close_missing=True)
        self.assertEqual(rescan.closed, 2)  # SQL injection and the SameSite cookie
        self.assertEqual(rescan.known, 5)  # /profile/2048/edit is the same endpoint as /profile/1024/edit
        sqli = self.find("CWE-89", "/api/products")
        self.assertEqual(sqli["status"], "fixed")
        self.assertEqual(sqli["closed_at"], (TODAY + timedelta(days=10)).isoformat())
        self.assertEqual(self.find("CVE-2021-41773")["status"], "open")  # other scanner's finding untouched

        regression_day = TODAY + timedelta(days=20)
        back = self.ingest("zap_report.json", regression_day)
        self.assertEqual(back.reopened, 2)
        sqli = self.find("CWE-89", "/api/products")
        self.assertEqual((sqli["status"], sqli["reopen_count"]), ("open", 1))
        self.assertEqual(sqli["due_date"], (regression_day + timedelta(days=7)).isoformat())
        self.assertEqual([e["kind"] for e in events_for(self.conn, sqli["id"])], ["created", "severity", "status", "reopened"])

    def test_close_missing_requires_asset(self):
        with self.assertRaises(ValueError):
            import_report(self.conn, load(SAMPLES / "zap_report.json"), TODAY, close_missing=True)

    def test_without_asset_findings_group_by_host(self):
        import_report(self.conn, load(SAMPLES / "zap_report.json"), TODAY)
        import_report(self.conn, load(SAMPLES / "semgrep.sarif"), TODAY)
        assets = {r[0] for r in self.conn.execute("SELECT DISTINCT asset FROM findings")}
        self.assertEqual(assets, {"shop.example.test", "codebase"})

    def test_analyst_cvss_overrides_scanner_severity(self):
        self.ingest("zap_report.json")
        xss = self.find("CWE-79")
        updated = update_finding(self.conn, xss["id"], TODAY, cvss=XSS_VECTOR, owner="team-search", status="in_progress")
        self.assertEqual((updated["cvss_score"], updated["severity"]), (6.1, "medium"))
        self.assertEqual(updated["due_date"], (TODAY + timedelta(days=90)).isoformat())
        self.assertEqual(updated["owner"], "team-search")

        self.ingest("zap_report.json", TODAY + timedelta(days=1))
        self.assertEqual(self.find("CWE-79")["severity"], "medium")  # rescan does not undo triage

    def test_risk_acceptance_needs_justification_and_survives_rescans(self):
        self.ingest("zap_report.json")
        cookie = self.find("zap:10054")
        with self.assertRaises(ValueError):
            update_finding(self.conn, cookie["id"], TODAY, status="risk_accepted")
        update_finding(self.conn, cookie["id"], TODAY, status="risk_accepted", comment="компенсирующая мера: CSRF-токены")
        self.ingest("zap_report.json", TODAY + timedelta(days=3))
        self.assertEqual(self.find("zap:10054")["status"], "risk_accepted")

    def test_manual_reopen_restarts_sla(self):
        self.ingest("zap_report.json")
        xss = self.find("CWE-79")
        update_finding(self.conn, xss["id"], TODAY, status="fixed")
        later = TODAY + timedelta(days=5)
        reopened = update_finding(self.conn, xss["id"], later, status="open", comment="фикс не помог")
        self.assertEqual(reopened["reopen_count"], 1)
        self.assertEqual(reopened["due_date"], (later + timedelta(days=30)).isoformat())

    def test_overdue_and_ordering(self):
        self.ingest("zap_report.json")
        self.ingest("nuclei_results.jsonl")
        overdue = list_findings(self.conn, TODAY + timedelta(days=31), overdue=True)
        self.assertEqual({r["severity"] for r in overdue}, {"critical", "high"})
        ordered = [r["severity"] for r in list_findings(self.conn, TODAY)]
        self.assertEqual(ordered[0], "critical")
        self.assertEqual(ordered[-1], "info")

    def test_summary_mttr(self):
        self.ingest("zap_report.json")
        self.ingest("nuclei_results.jsonl")
        self.ingest("zap_report_rescan.json", TODAY + timedelta(days=10), close_missing=True)
        stats = summary(self.conn, TODAY + timedelta(days=10), "demo-shop")
        self.assertEqual(stats.closed["fixed"], 2)
        self.assertEqual(stats.mttr_days, 10.0)
        self.assertEqual(stats.active["critical"], 0)
        self.assertEqual(stats.active["high"], 2)  # XSS and CVE-2021-41773

    def test_unknown_finding(self):
        with self.assertRaises(FindingNotFound):
            update_finding(self.conn, 999, TODAY, status="fixed")


if __name__ == "__main__":
    unittest.main()
