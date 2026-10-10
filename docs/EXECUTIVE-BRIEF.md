# Executive brief: accountable agentic AI

**Decision:** use this reference to evaluate a bounded sandbox pilot. Do not infer production readiness from the demonstration.

## Business opportunity

Agents can reduce coordination overhead in discovery, ticketing and remediation workflows. Connecting those capabilities to privileged tools changes the risk: a natural-language suggestion can become an operational change. Governance should define the agent's purpose and authority before that connection is made.

## Demonstrated controls

The working gate evaluates an explicit mandate, requires independent approval for material impact, rechecks budget and stop state at reservation, refuses request replay and records an HMAC audit chain. The fixture demonstration includes nine synthetic scenarios; three complete and six are blocked. No cloud or network action occurs.

## Conditions for progressing

Authenticate participants; derive trusted data/resource labels; enforce mediation at the connector; limit real cost and destinations; test timeout, cancellation and idempotency; independently anchor audit checkpoints; and review residual risk with a named owner.

## Residual exposure

The gate does not know whether agent-supplied metadata is true. A callback can bypass it unless the platform prevents that. An external side effect is not atomic with SQLite. An emergency stop does not cancel already-running work. Audit tail removal requires an external anchor to detect. Host/key compromise defeats these reference controls.

## Evidence to request

Run the test suite and synthetic report; inspect denied and approved paths, negative approval tests, concurrency behavior and anchored audit verification. Review the threat model and development decisions. Obtain actual connector and operational evidence before expanding the pilot.

Prepared with OpenAI Codex assistance. This is an illustrative executive analysis, not a claim about the portfolio owner's authored work or professional achievements.
