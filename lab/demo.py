"""Runs every scenario twice: agent wired directly to the EDR, then through the gateway.

    python -m lab.demo            summary table
    python -m lab.demo -v         every tool call with its verdict
"""
import sys
from pathlib import Path

from lab.audit import AuditLog
from lab.edr import MockEDR
from lab.gateway import DirectTools, ToolGateway
from lab.scenarios import SCENARIOS, outcome, run

KEY = "edr-lab-key-123"
OUT = Path(__file__).resolve().parent.parent / "out"


def main():
    verbose = "-v" in sys.argv
    rows = []
    for s in SCENARIOS:
        direct = run(s, DirectTools(MockEDR(KEY), KEY))
        audit = AuditLog(OUT / f"audit-{s.key}.jsonl")
        gateway = ToolGateway(MockEDR(KEY), KEY, audit)
        guarded = run(s, gateway)
        rows.append((s, outcome(s, direct), outcome(s, guarded), _control(guarded)))
        if verbose:
            print(f"\n## {s.title}  [{s.owasp}]  source: {s.source}")
            previous, repeats = None, 0
            for r in guarded + [None]:
                line = r and f" {'!' if r['malicious'] else ' '} {r['tool']:<13} {r['status']:<17} {r['reason']}"
                if line == previous:
                    repeats += 1
                    continue
                if repeats:
                    print(f"   ... same line {repeats} more time(s)")
                if line:
                    print(line)
                previous, repeats = line, 0

    print("\n| Scenario | OWASP LLM | Without gateway | With gateway | Stopped by |")
    print("|---|---|---|---|---|")
    for s, before, after, control in rows:
        print(f"| {s.title} | {s.owasp} | {before} | {after} | {control} |")

    stopped = sum(after == "STOPPED" for s, _, after, _ in rows if s.key != "legit")
    attacks = len(rows) - 1
    print(f"\nAttacks stopped: {stopped}/{attacks} with the gateway, "
          f"{sum(b == 'STOPPED' for s, b, _, _ in rows if s.key != 'legit')}/{attacks} without.")
    print(f"Audit logs: {OUT}")
    _tamper_demo()


def _control(results):
    reasons = [r["reason"] for r in results if r["malicious"] and r["status"] != "allowed"]
    return reasons[0] if reasons else "-"


def _tamper_demo():
    """Shows that editing an audit entry after the fact is detected."""
    log = OUT / "audit-dismiss.jsonl"
    audit = AuditLog.__new__(AuditLog)
    audit.path = log
    before = audit.verify()
    lines = log.read_text(encoding="utf-8").splitlines()
    lines[-1] = lines[-1].replace("pending_approval", "allowed")
    tampered = OUT / "audit-dismiss.tampered.jsonl"
    tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")
    audit.path = tampered
    after = audit.verify()
    print(f"Audit chain intact: {before[0]}. After editing one entry: intact={after[0]}, "
          f"broken at line {after[1]}.")


if __name__ == "__main__":
    main()
