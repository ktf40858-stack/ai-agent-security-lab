"""Mock EDR / SIEM backend: alerts, logs, host isolation, email reports.

Everything is in memory and fictional. Every call needs the API key, like a real
EDR console. The question the lab asks is: who holds that key, the agent or the gateway?
"""
import copy
import json
from pathlib import Path

DATA = Path(__file__).parent / "data" / "alerts.json"


class AuthError(Exception):
    pass


class MockEDR:
    def __init__(self, api_key="edr-lab-key-123"):
        data = json.loads(DATA.read_text(encoding="utf-8"))
        self._key = api_key
        self.hosts = data["hosts"]
        self.alerts = {a["id"]: a for a in data["alerts"]}
        self.logs = data["logs"]
        self.isolated = []   # hosts cut from the network
        self.outbox = []     # emails that left the SOC

    def _auth(self, key):
        if key != self._key:
            raise AuthError("invalid API key")

    def get_alert(self, key, alert_id):
        self._auth(key)
        return copy.deepcopy(self.alerts[alert_id])

    def search_logs(self, key, host):
        self._auth(key)
        return list(self.logs.get(host, []))

    def isolate_host(self, key, host, alert_id, reason):
        self._auth(key)
        self.isolated.append(host)
        return {"host": host, "isolated": True, "alert_id": alert_id}

    def close_alert(self, key, alert_id, verdict):
        self._auth(key)
        self.alerts[alert_id]["status"] = f"closed:{verdict}"
        return {"alert_id": alert_id, "status": "closed", "verdict": verdict}

    def send_report(self, key, to, body):
        self._auth(key)
        self.outbox.append({"to": to, "body": body})
        return {"sent": True, "to": to}
