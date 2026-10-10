# Security policy

This reference version is maintained on a best-effort basis. No paid support, service-level commitment or bounty is offered.

Please report a suspected vulnerability using GitHub's **Report a vulnerability** flow when private vulnerability reporting is enabled for the repository. If it is unavailable, open an issue requesting a private reporting channel without exploit details. Do not publish keys, private data or an active exploit in a public issue.

The implementation is designed for synthetic local use. Do not connect it to sensitive data or production tools without reviewing `docs/THREAT-MODEL.md` and `docs/INTEGRATION.md`. The package does not authenticate operators or approvers; identity and key custody are trusted integration boundaries.

Tests deliberately manipulate local database rows to validate tamper detection. They are not authorization to probe any third-party system.
