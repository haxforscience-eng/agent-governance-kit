# Validation record

Initial local verification, 9 October 2026:

- Python 3.11+ standard-library unittest suite: **23 test methods passed**. Parameterized subtests cover additional refusal cases.
- Synthetic demo: **9 scenarios; 3 fixture executions completed; 6 blocked**.
- Audit chain verified by the Python gate against its exported final head.
- Two-thread concurrent reservation test: one callback and one refusal, with one cost reservation.
- Approval signature/binding/expiry/storage and self-approval tests passed.
- Replay, budget, stop, policy-change and stored-intent mutation tests passed.
- Tail truncation test confirms that verification without an independently retained head cannot detect removal of the tail.

The suite is local verification, not independent security assurance. Hosted CI results should be read from GitHub once workflows run. No production adapter, cloud action, authenticated identity integration or penetration test was performed.

Review commands and expected exit codes are in README.md. The full test log is supplied separately with the delivery package.
