# Threat model: AI SOC triage agent

## System

An LLM-based agent triages EDR/SIEM alerts for a SOC. It can call five tools: `get_alert`,
`search_logs`, `isolate_host`, `close_alert`, `send_report`. All tool calls go through a tool
gateway that holds the EDR API key and enforces policy.

## Assets

| Asset | Why it matters |
|---|---|
| EDR API key | Full control of endpoint containment across the fleet |
| Availability of critical hosts (domain controller, firewall, database) | Isolating them is an outage |
| Alert integrity | A wrongly closed critical alert is a missed intrusion |
| Log data | Hostnames, users, internal IPs: valuable reconnaissance |
| Audit trail | The only record of what the agent did and why |

## Trust boundaries

1. **Alert data → agent.** Alert fields (user agents, file names, comments, email subjects) are
   written by whoever triggered the alert, which can be the attacker. Everything the agent reads
   is untrusted input.
2. **Agent → gateway.** The model's output is untrusted too: it may have been steered by
   boundary 1, or simply be wrong. The gateway treats every request as hostile until validated.
3. **Gateway → EDR.** Trusted, authenticated with a key the agent never sees.
4. **Gateway → human.** Sensitive actions leave the automated path and wait for an analyst.

## STRIDE

| Threat | Example in this system | Control | Status |
|---|---|---|---|
| **Spoofing** | Injected text claims to be a "SYSTEM NOTE" or an "authorized red team" | Authority never comes from data: policy decides, instructions in alerts carry no weight; the live agent's prompt marks tool output as untrusted | Mitigated by policy; the model may still be confused |
| **Tampering** | Agent passes `ws-042; isolate --all` or extra arguments to a tool | Exact argument keys, regex validation, length limits | Mitigated |
| **Tampering** | Someone edits the audit log to hide an action | Hash chain detects edits and deletions | Partially: a full rewrite needs an external anchor |
| **Repudiation** | "The agent never isolated that host" | Every request logged with verdict and reason, allowed or not | Mitigated |
| **Information disclosure** | Agent is asked to print its configuration or email logs outside | Key held only by the gateway; recipient domain allowlist | Mitigated |
| **Information disclosure** | Agent writes sensitive log lines into an internal report | Not controlled: internal reports are allowed to contain logs | Accepted |
| **Denial of service** | Injection triggers isolation of every host, or of the domain controller | Isolation must match the alert's host; critical assets need approval; isolation limit per run | Mitigated |
| **Denial of service** | Runaway loop burns API quota and tokens | Call budget per run | Mitigated |
| **Elevation of privilege** | Agent closes a critical alert, acting beyond Tier 1 authority | Dismissing high/critical alerts needs approval | Mitigated |

## Residual risks

- **In-policy manipulation.** An injection can still push the agent toward actions the policy
  allows: isolating the alert's own workstation, or closing a low-severity alert. The impact is
  bounded by design, which is the point of the policy.
- **Approval fatigue.** A flood of injected alerts could fill the approval queue so analysts
  approve without reading. Mitigation to add: rate-limit approvals, show the triggering alert text
  next to each request.
- **Gateway compromise.** The gateway becomes the crown jewel. In production: separate service,
  least-privilege EDR key (containment scope only), secret manager, its own monitoring.
- **Detection of the injection itself.** The lab blocks the effects but does not flag the alert
  that carried the injection. A next step is to raise a separate alert whenever a blocked or
  pending action was requested, since that is a strong signal of manipulation.

## OWASP Top 10 for LLM Applications 2025: coverage

| ID | Risk | Covered by |
|---|---|---|
| LLM01 | Prompt Injection | Scenarios `redirect`, `dismiss`; alert-bound isolation, approvals |
| LLM02 | Sensitive Information Disclosure | Scenarios `exfiltration`, `credential-theft`; key isolation, recipient allowlist |
| LLM05 | Improper Output Handling | Scenario `arg-injection`; strict argument validation |
| LLM06 | Excessive Agency | Scenarios `redirect`, `mass-isolation`; least privilege, approvals, isolation limit |
| LLM10 | Unbounded Consumption | Scenario `runaway-loop`; call budget |
| LLM07 | System Prompt Leakage | Not tested: the system prompt holds no secret by design |
| LLM03, 04, 08, 09 | Supply chain, poisoning, embeddings, misinformation | Out of scope for this lab |
