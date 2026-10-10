# Agentic AI governance — synthetic assurance brief

**Status:** reference demonstration; no production assurance or compliance certification.

## Executive decision

Proceed with a bounded sandbox pilot only. Production connectivity requires authenticated identities, trusted resource metadata, independent key custody, enforced tool mediation, external audit anchoring, and operational recovery testing.

## Measured demonstration

9 synthetic scenarios: 3 completed through fixture adapters, 6 blocked. No network or cloud actions were performed.

| Scenario | Policy | Execution |
| --- | --- | --- |
| Bounded discovery | allow | completed |
| Controlled change | review | completed |
| Production intervention | review | completed |
| Unapproved production action | review | blocked |
| Unexpected destination | deny | blocked |
| Privilege expansion | deny | blocked |
| Sensitive data boundary | deny | blocked |
| Budget boundary | deny | blocked |
| Emergency intervention | deny | blocked |

## Evidence and ownership

HMAC audit chain verified against the exported head: True. The supplied head must be retained independently to detect tail truncation. The verifier uses a secret key that is deliberately not included in this report.

Business owner: define purpose and acceptable impact. Security owner: approve permissions and connectors. Risk officer: approve production exceptions. Platform owner: enforce the gateway and monitor failures.

## What this does not prove

The gate cannot authenticate a human by itself, establish true data classification from agent assertions, prevent tools from bypassing it, stop an already-running callback, or make an external side effect atomic with SQLite. It does not detect prompt injection semantically. It constrains declared actions independently of model prose.

## Next assurance gates

1. Bind agent and approver identity to enterprise identity services.
2. Derive resource labels and actual cost ceilings from trusted adapters.
3. Exercise abort, timeout and idempotency behavior with a real connector.
4. Anchor signed audit checkpoints outside the execution host.
5. Obtain a reviewed pilot risk acceptance and measurable rollout criteria.

All organization, identity, resource and transaction data in this report is synthetic. Code and documentation were prepared with OpenAI Codex; portfolio-owner authorship and career achievements are not asserted.
