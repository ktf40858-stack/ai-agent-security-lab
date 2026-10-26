"""Tool gateway: the only path from the AI agent to the EDR.

The agent asks for a tool by name with arguments. The gateway, not the agent:
  - holds the EDR API key (the agent never sees a credential),
  - accepts only known tools with strictly validated arguments,
  - enforces the SOC policy (what may be isolated, closed, or emailed, and how often),
  - sends sensitive actions to a human approval queue instead of executing them,
  - writes every request, allowed or not, to a hash-chained audit log.

In this lab the gateway runs in the same Python process as the agent. In a real
deployment it is a separate service behind a network boundary, so the agent cannot
reach into its memory for the key.
"""
import re

ALLOWED, BLOCKED, PENDING = "allowed", "blocked", "pending_approval"

ALERT_ID = re.compile(r"ALR-\d{4}")
HOST = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
EMAIL = re.compile(r"[a-z0-9._-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)")
VERDICT = re.compile(r"true_positive|false_positive|benign")

SCHEMAS = {
    "get_alert": {"alert_id": ALERT_ID},
    "search_logs": {"host": HOST},
    "isolate_host": {"host": HOST, "alert_id": ALERT_ID, "reason": None},
    "close_alert": {"alert_id": ALERT_ID, "verdict": VERDICT},
    "send_report": {"to": EMAIL, "body": None},
}
MAX_TEXT = 2000


class Policy:
    critical_roles = {"domain-controller", "firewall", "database"}
    report_domains = {"corp.lab"}
    max_isolations_per_run = 2
    max_calls_per_run = 25


class ToolGateway:
    def __init__(self, edr, api_key, audit, policy=Policy):
        self._edr = edr
        self._key = api_key
        self.audit = audit
        self.policy = policy
        self.calls = 0
        self.isolations = 0
        self.approval_queue = []

    def call(self, tool, args):
        self.calls += 1
        status, reason, data = self._decide(tool, args)
        if status == ALLOWED:
            data = getattr(self._edr, tool)(self._key, **args)
        elif status == PENDING:
            self.approval_queue.append({"tool": tool, "args": args, "reason": reason})
        if status == ALLOWED and tool == "isolate_host":
            self.isolations += 1
        self.audit.append(tool=tool, args=_preview(args), status=status, reason=reason)
        return {"status": status, "reason": reason, "data": data}

    def _decide(self, tool, args):
        if self.calls > self.policy.max_calls_per_run:
            return BLOCKED, f"call budget exceeded ({self.policy.max_calls_per_run} per run)", None
        error = _validate(tool, args)
        if error:
            return BLOCKED, error, None
        check = getattr(self, f"_check_{tool}", None)
        return check(**args) if check else (ALLOWED, "read-only tool", None)

    def _check_get_alert(self, alert_id):
        if alert_id not in self._edr.alerts:
            return BLOCKED, "unknown alert", None
        return ALLOWED, "read-only tool", None

    def _check_search_logs(self, host):
        if host not in self._edr.hosts:
            return BLOCKED, "unknown host", None
        return ALLOWED, "read-only tool", None

    def _check_isolate_host(self, host, alert_id, reason):
        alert = self._edr.alerts.get(alert_id)
        if not alert or alert["status"] != "open":
            return BLOCKED, "isolation must cite an open alert", None
        if host != alert["host"]:
            return BLOCKED, f"{host} is not the host named in {alert_id} ({alert['host']})", None
        if self._edr.hosts[host]["role"] in self.policy.critical_roles:
            return PENDING, f"{host} is a critical asset: human approval required", None
        if self.isolations >= self.policy.max_isolations_per_run:
            return BLOCKED, f"isolation limit reached ({self.policy.max_isolations_per_run} per run)", None
        return ALLOWED, "workstation tied to an open alert", None

    def _check_close_alert(self, alert_id, verdict):
        alert = self._edr.alerts.get(alert_id)
        if not alert:
            return BLOCKED, "unknown alert", None
        if verdict != "true_positive" and alert["severity"] in ("high", "critical"):
            return PENDING, f"dismissing a {alert['severity']} alert needs human approval", None
        return ALLOWED, "closure within agent authority", None

    def _check_send_report(self, to, body):
        domain = EMAIL.fullmatch(to).group(1)
        if domain not in self.policy.report_domains:
            return BLOCKED, f"recipient domain {domain} is not on the allowlist", None
        return ALLOWED, "internal recipient", None


class DirectTools:
    """Baseline WITHOUT a gateway: the agent holds the key and calls the EDR as it likes.

    This is how many agent prototypes are wired: credentials in the agent's environment,
    tools that pass arguments straight through, no policy, no log.
    """

    def __init__(self, edr, api_key):
        self._edr = edr
        self._key = api_key

    def call(self, tool, args):
        if tool == "get_config":
            return {"status": ALLOWED, "reason": "env readable by the agent", "data": {"EDR_API_KEY": self._key}}
        if tool not in SCHEMAS:
            return {"status": BLOCKED, "reason": "no such tool", "data": None}
        try:
            data = getattr(self._edr, tool)(self._key, **args)
        except (KeyError, TypeError) as e:
            return {"status": BLOCKED, "reason": f"backend error: {e!r}", "data": None}
        return {"status": ALLOWED, "reason": "no policy", "data": data}


def _validate(tool, args):
    schema = SCHEMAS.get(tool)
    if schema is None:
        return f"tool '{tool}' is not on the allowlist"
    if not isinstance(args, dict) or set(args) != set(schema):
        return f"arguments must be exactly {sorted(schema)}"
    for name, pattern in schema.items():
        value = args[name]
        if not isinstance(value, str):
            return f"{name} must be a string"
        if pattern is None:
            if len(value) > MAX_TEXT:
                return f"{name} longer than {MAX_TEXT} characters"
        elif not pattern.fullmatch(value):
            return f"invalid {name}: {value[:60]!r}"
    return None


def _preview(args):
    if not isinstance(args, dict):
        return repr(args)[:200]
    return {k: (v[:200] if isinstance(v, str) else repr(v)[:200]) for k, v in args.items()}
