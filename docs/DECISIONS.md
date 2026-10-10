# Development decision record

Date: 9 October 2026 (America/New_York). Initial reference release: 0.1.0.

| Decision | Rationale | Trade-off / review trigger |
| --- | --- | --- |
| Separate policy evaluation from execution | A proposed action is not an authorization | Integrations must force all tool invocations through the gate |
| Python standard library, no model SDK | Keeps the control reviewable and runnable without accounts or paid services | Not a drop-in framework adapter; a production connector requires work |
| Explicit tool registry and grants | Agent prose cannot expand authority; unknown tools fail closed | Grants need an administrator and a renewal process |
| Canonical, narrow resource URIs | Prefix matching uses a segment boundary, avoiding adjacent-prefix confusion and traversal | Does not support arbitrary cloud ARN syntax; adapter normalizes trusted identifiers |
| Exact HTTPS egress hosts | Avoids suffix-based allowlist confusion | Does not resolve DNS, inspect redirects or enforce sockets; connector must enforce |
| Owner review for writes/exports/admin and confidential reads | Material effects and sensitive reads receive independent oversight | Static role requirements; organizations must review their own risk tiers |
| Two roles for material production changes | Makes separation of duties demonstrable | Role assertions require authenticated human identity in the signer |
| HMAC tokens bound to intent and policy | Prevents substitution, forgery with no key, expiry bypass and replay | Shared-secret issuer and verifier both remain highly trusted |
| Distinct approval and audit keys | Limits accidental cross-use and clarifies custody | No key rotation migration in 0.1.0; do not silently replace keys for an existing database |
| SQLite BEGIN IMMEDIATE reservation | Checks current budget/stop state and claims a request atomically on one host | Database lifetime cap; no distributed store, no external transaction |
| Reserve before callback, retain on failure | Refuses duplicate effects after ambiguity or crash | A crash may leave `executing` forever; investigation rather than automatic retry |
| HMAC audit chain plus independent head | Detects modification/reordering; an external head exposes tail truncation | Cannot withstand a fully compromised gate/key holder; not immutable storage |
| Log metadata, not prompt or callback output | Keeps synthetic evidence focused and avoids logging arbitrary secrets | Identifiers themselves may be sensitive in a real system; classification and retention review required |
| Export real demo receipts to a static website | Executive readers can inspect measured behavior without server attack surface | Browser displays the export; it does not cryptographically verify it |
| Editorial portfolio with restrained green/ivory palette | Communicates executive judgment through substance rather than programming spectacle | Career details remain a clearly disclosed preview until verified |
| Preserve AI authorship disclosure | Prevents portfolio work from becoming an invented personal achievement | Owner must review and contextualize before using it as a work sample |

## Validation-driven corrections

- The first test pass exposed a timestamp bound intended for costs being reused for Unix timestamps. Approval timestamps now use an explicit larger bound; costs remain independently bounded.
- Added a stored intent fingerprint to detect accidental request mutation before execution.
- Rejected approval and execution attempts emit bounded, metadata-only audit events.
- Approval storage fields are checked against signed claims at execution, not trusted on their own.
- Audit verification is checked before a new execution reservation.
- CI uses official action commits verified against their current release tags, Node 24 runtimes, a fixed Ubuntu 24.04 runner, read-only repository contents and no retained checkout credentials. Release pins require periodic review.

These corrections reflect local testing, not an independent security audit. Further findings and changes belong in this record.
