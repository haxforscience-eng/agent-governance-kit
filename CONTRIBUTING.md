# Contributing

Start with an issue describing the decision or security property you want to improve. Keep implementation changes small and explain their effect on the threat model. Avoid adding live cloud actions, model dependencies or implicit authorization.

1. Use Python 3.11+ and standard-library modules where practical.
2. Run `PYTHONPATH=src python -m unittest discover -s tests -v` (PowerShell: set `$env:PYTHONPATH='src'` first).
3. Add behavioral tests for changed security properties. Include refusal cases and test boundaries.
4. Run the demo and verify that the executive report still matches actual outcomes.
5. Document new trusted inputs, assumptions, residual risks and schema changes.
6. Use synthetic data only; disclose material AI assistance in the pull request.

Do not update synthetic evidence solely to make a test pass. Explain changed outcomes. No contributor license agreement is required; contributions use the project's MIT license.
