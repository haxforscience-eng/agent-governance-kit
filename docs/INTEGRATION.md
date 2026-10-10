# Integration guide

## Start with the trust boundary

Do not hand an agent the signing key, audit key, direct tool credentials or an unrestricted `GovernanceGate` object. The trusted platform service should own the gate and resolve the request from authenticated context. A tool adapter must enforce the exact declared resource, operation, destination and hard cost ceiling. The agent may only propose an action.

The following is a **synthetic API sketch**, not a deployed production service:

```python
import secrets
import time
from agent_governance import Intent, Policy, GovernanceGate, ApprovalIssuer

# Load administrator-reviewed policy; keep keys outside the SQLite database.
approval_key = secrets.token_bytes(32)
audit_key = secrets.token_bytes(32)
issuer = ApprovalIssuer(approval_key)
gate = GovernanceGate(policy, 'synthetic.db', approval_key, audit_key)
try:
    request = gate.submit(Intent.from_dict(trusted_intent_metadata))
    # Only a trusted issuer authenticated as the named human may issue this.
    token = issuer.issue(request, 'business-owner', 'owner', int(time.time()), 300)
    gate.approve(token)
    # This callback is intentionally fixture-only.
    result = gate.execute(request['request_id'], lambda intent: {'synthetic': True})
    checkpoint = gate.evidence()['audit_head']
    assert gate.verify_audit(checkpoint)['valid']
finally:
    gate.close()
```

Use real authenticated identity in a separately reviewed signer. `ApprovalIssuer.issue` does not authenticate a caller; possessing the key can sign any identity. Tokens require a role present in policy and cannot approve the requester or agent itself. Production material changes need both `owner` and `risk` roles.

## Required production engineering

- Authenticate agents, requesters, approvers and emergency-stop operators; bind their identifiers to enterprise identity.
- Resolve environment, tenant, classification and canonical resource scope from administrator-owned inventories.
- Supply dedicated key custody and access control, recoverable backups and a deliberate key-rotation/migration design. Reuse the correct keys for a persisted database; changing them silently breaks outstanding approvals and verification.
- Give the agent no direct connector credentials. Enforce mediation, redirects, DNS/address policy, timeouts, output filtering and actual action cost.
- Use connector idempotency keys and an explicit recovery process. Investigate `executing` or `failed` requests; this reference never retries a request automatically.
- Define retention, availability and capacity limits. Protect the SQLite file, backups and host; use a supported single-host topology with local durable storage.
- Export audit checkpoints to an independent authority after transitions. Verify against those anchors during review; a digest stored beside the database is not independent custody.
- Review pilot risk acceptance, exercise incident response and restrict rollback authority before enabling production changes.

## Policy lifecycle

Policy version 1 has a strict field contract; unexpected keys and unsupported values are rejected. A canonical SHA-256 fingerprint binds the entire policy. A new policy fingerprint invalidates pending work and associated approvals; submit a new request. Do not replace a tool's effect in-place to hide an impact change.

The cost cap is in integer cents, aggregated across the database's lifetime. Failed or ambiguous executions retain their reservation. No refund/reset endpoint is supplied.

## Deployment posture

The initial release is a Python library plus local CLI. It has no public listener, authentication service or production deployment manifest. Start in a isolated synthetic environment. A production service wrapper is intentionally outside this release; adding one requires a separate architecture and security review.
