# Threat model

## Purpose and assets

Protect the relationship between an administrator's declared agent mandate and a mediated tool invocation. Assets: policy authority, approval integrity, single-use request state, bounded reserved cost and decision evidence.

## Actors and trusted boundaries

- **Agent / prompt input:** untrusted. May propose a tool, resource or destination outside its grant. Model output does not authorize anything.
- **Adapter:** trusted to authenticate the agent/requester and derive correct resource, environment, classification and estimated cost metadata. The supplied demo metadata is synthetic. Self-declared labels cannot be trusted for real decisions.
- **Approval issuer:** trusted to authenticate the approver, validate their role and hold the signing key. A supplied string is not identity verification.
- **Platform operator:** trusted to manage policy, the emergency stop, keys and local database permissions. No operator authentication is implemented here.
- **Tool callback:** trusted to implement exactly the declared action, enforce egress and cost bounds, and avoid bypassing mediation.
- **Execution host and keys:** trusted. An attacker with control of the process and keys can forge approvals/evidence or bypass the gate.

## Threats addressed in the reference

| Threat | Control | Demonstration |
| --- | --- | --- |
| Tool or resource privilege expansion | Registry, agent grant, segment-aware canonical resource scope | Unknown shell tool; adjacent resource prefix tests |
| Declared export to an unapproved host | HTTPS parsing and exact DNS hostname allowlist | Confusable suffix and invalid scheme tests |
| High-impact action without oversight | Owner and risk roles for production changes | One role blocks; both roles allow |
| Forged, substituted or stale approval | HMAC signature, request/intent/policy binding and strict expiry | Signature, digest, role and clock tests |
| Self-approval or duplicate role counting | Requester/agent separation and one stored approval per approver | Self-approval and duplicate tests |
| Replay / racing executions | Atomic pending→executing reservation | Two threads, independent connections, exactly one callback |
| Budget race or stale stop check | Reevaluate runtime state inside reservation transaction | Competing pending requests and post-approval stop tests |
| Audit body mutation, gaps or reordering | Sequence, previous MAC and HMAC recomputation | Tamper tests |
| Tail truncation | Compare to independently retained expected head | Truncation passes unanchored verification and fails anchored verification |

## Residual risks and non-goals

1. **Input truth:** the gate cannot discover the real classification, tenant, actual cost or tool behavior. Derive them from trusted systems.
2. **Bypass:** agents with direct credentials or unmediated tool access can bypass a policy gate entirely.
3. **Network:** exact-host checks do not control redirects, DNS rebinding, proxy behavior, resolved addresses or sockets.
4. **Side effects:** callback execution is outside the database transaction. A crash can happen after an external effect and before the completion record. Requests stay non-replayable, and operators must investigate.
5. **Intervention latency:** the emergency stop affects future reservations, not callbacks already reserved or running. Connectors need cancellation/timeout mechanisms.
6. **Cost:** estimated reserved cents are capped for the database's lifetime. They are not actual metered cost, daily limits, refunds or financial authorization.
7. **Audit custody:** without an external anchor, removing the tail is not detectable. HMAC verification requires the secret key; the browser's exported status is not independent verification. Full host/key compromise defeats the chain.
8. **Persistence and recovery:** there is no automatic key rotation, distributed replication, migration, retry, recovery service or approval identity provider.
9. **Abuse and availability:** no API rate limiter is included. Privileged callers can flood metadata records. Use a bounded adapter and retention policy.
10. **Prompt injection:** this does not classify malicious language. It constrains a declared action regardless of the prompt that suggested it.

This reference should be used to review architecture and tests, not as an assurance that a real agent deployment is secure.
