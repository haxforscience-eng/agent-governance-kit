"""Synthetic scenarios: no cloud SDK, model, network or real tool execution."""
from __future__ import annotations
import json
import secrets
import tempfile
from pathlib import Path
from .gate import ApprovalIssuer, GovernanceGate, GovernanceError
from .policy import Intent, Policy


def run_demo(policy: Policy) -> dict:
    now = 1_800_000_000
    approval_key, audit_key = secrets.token_bytes(32), secrets.token_bytes(32)
    issuer = ApprovalIssuer(approval_key)
    base = {"agent_id": "cloud-advisor", "requester_id": "synthetic-operator", "tool": "inventory.read", "resource": "cloud://synthetic-account/compute/service-a", "environment": "sandbox", "classification": "internal", "estimated_cost_cents": 25}
    scenarios = [
        ("Bounded discovery", "Read synthetic cloud inventory within an explicit mandate.", {}, [], False),
        ("Controlled change", "Create a staging remediation ticket after the business owner approves.", {"tool": "ticket.create", "environment": "staging"}, ["business-owner"], False),
        ("Production intervention", "A production change requires both the business owner and risk officer.", {"tool": "cloud.change", "environment": "production"}, ["business-owner", "risk-officer"], False),
        ("Unapproved production action", "One approval cannot satisfy two independent roles.", {"tool": "cloud.change", "environment": "production"}, ["business-owner"], False),
        ("Unexpected destination", "An export destination outside the exact egress allowlist is denied.", {"tool": "evidence.export", "destination": "https://untrusted.example.net/receive"}, [], False),
        ("Privilege expansion", "A known agent attempts an unregistered shell tool.", {"tool": "shell.execute"}, [], False),
        ("Sensitive data boundary", "Restricted data exceeds the agent's confidential ceiling.", {"classification": "restricted"}, [], False),
        ("Budget boundary", "An invocation exceeds the database-lifetime reserved cost cap.", {"estimated_cost_cents": 1001}, [], False),
        ("Emergency intervention", "An operator stop prevents new reservations, including approved work.", {}, [], True),
    ]
    results = []
    with tempfile.TemporaryDirectory(prefix="agent-governance-demo-") as folder:
        gate = GovernanceGate(policy, str(Path(folder) / "demo.db"), approval_key, audit_key, lambda: now)
        try:
            for title, description, changes, approvers, stopped in scenarios:
                if stopped:
                    gate.set_emergency_stop(True, "synthetic-operator")
                intent = Intent.from_dict(base | changes)
                request = gate.submit(intent)
                for approver in approvers:
                    gate.approve(issuer.issue(request, approver, policy.data["approvers"][approver], now, 300))
                executions = []
                try:
                    result = gate.execute(request["request_id"], lambda i: executions.append(i.tool) or {"synthetic": True, "operation": i.tool, "message": "Fixture adapter completed; no external side effects."})
                except GovernanceError as exc:
                    result = {"status": "blocked", "reason": str(exc)}
                replay_blocked = None
                if result["status"] == "completed":
                    try:
                        gate.execute(request["request_id"], lambda i: executions.append(i.tool))
                    except GovernanceError:
                        replay_blocked = True
                results.append({"id": f"scenario-{len(results)+1}", "title": title, "description": description, "intent": intent.to_dict(), "decision": request["decision"], "approvals": approvers, "execution": result, "adapter_calls": len(executions), "replay_blocked": replay_blocked})
            evidence = gate.evidence()
            verified = gate.verify_audit(evidence["audit_head"])
            return {"schema_version": 1, "synthetic": True, "project": "Agent Governance Kit", "generated_by": "Python reference gate v0.1.0", "scenarios": results, "evidence": evidence, "verification": verified, "summary": {"scenarios": len(results), "completed": sum(x["execution"]["status"] == "completed" for x in results), "blocked": sum(x["execution"]["status"] == "blocked" for x in results)}}
        finally:
            gate.close()


def write_report(data: dict, output: Path):
    output.mkdir(parents=True, exist_ok=True)
    (output / "evidence.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    lines = ["# Agentic AI governance — synthetic assurance brief", "", "**Status:** reference demonstration; no production assurance or compliance certification.", "", "## Executive decision", "", "Proceed with a bounded sandbox pilot only. Production connectivity requires authenticated identities, trusted resource metadata, independent key custody, enforced tool mediation, external audit anchoring, and operational recovery testing.", "", "## Measured demonstration", "", f"{data['summary']['scenarios']} synthetic scenarios: {data['summary']['completed']} completed through fixture adapters, {data['summary']['blocked']} blocked. No network or cloud actions were performed.", "", "| Scenario | Policy | Execution |", "| --- | --- | --- |"]
    lines += [f"| {s['title']} | {s['decision']['outcome']} | {s['execution']['status']} |" for s in data["scenarios"]]
    lines += ["", "## Evidence and ownership", "", f"HMAC audit chain verified against the exported head: {data['verification']['valid']}. The supplied head must be retained independently to detect tail truncation. The verifier uses a secret key that is deliberately not included in this report.", "", "Business owner: define purpose and acceptable impact. Security owner: approve permissions and connectors. Risk officer: approve production exceptions. Platform owner: enforce the gateway and monitor failures.", "", "## What this does not prove", "", "The gate cannot authenticate a human by itself, establish true data classification from agent assertions, prevent tools from bypassing it, stop an already-running callback, or make an external side effect atomic with SQLite. It does not detect prompt injection semantically. It constrains declared actions independently of model prose.", "", "## Next assurance gates", "", "1. Bind agent and approver identity to enterprise identity services.", "2. Derive resource labels and actual cost ceilings from trusted adapters.", "3. Exercise abort, timeout and idempotency behavior with a real connector.", "4. Anchor signed audit checkpoints outside the execution host.", "5. Obtain a reviewed pilot risk acceptance and measurable rollout criteria.", "", "All organization, identity, resource and transaction data in this report is synthetic. Code and documentation were prepared with OpenAI Codex; portfolio-owner authorship and career achievements are not asserted."]
    (output / "executive-brief.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

