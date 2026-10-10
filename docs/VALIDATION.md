# Validation record

Initial local verification, 9 October 2026:

- Local Python 3.12 standard-library unittest suite: **23 test methods passed**. Parameterized subtests cover additional refusal cases.
- Synthetic demo: **9 scenarios; 3 fixture executions completed; 6 blocked**.
- Audit chain verified by the Python gate against its exported final head.
- Two-thread concurrent reservation test: one callback and one refusal, with one cost reservation.
- Approval signature/binding/expiry/storage and self-approval tests passed.
- Replay, budget, stop, policy-change and stored-intent mutation tests passed.
- Tail truncation test confirms that verification without an independently retained head cannot detect removal of the tail.

GitHub Actions also passed on Python 3.11, 3.12 and 3.13 for source commit `3a89ca392a18005af60d7e373ada1f585564dbd4`: [verified run](https://github.com/haxforscience-eng/agent-governance-kit/actions/runs/38014663254). Read subsequent runs for the current revision.

These tests are implementation verification, not independent security assurance. No production adapter, cloud action, authenticated identity integration or penetration test was performed.

Review commands and expected exit codes are in README.md. The full test log is supplied separately with the delivery package.
