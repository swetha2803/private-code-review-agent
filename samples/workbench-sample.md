# Workbench Sample Inputs

Application / Module: Neo Mobile Payments

Development / CR Title: Add beneficiary transfer confirmation flow

Environment: SIT

Platform: Full stack

Applications / Teams / POCs:
- Mobile Team - Mobile POC - mobile.poc@example.test - UI and device testing
- Payments API - API POC - api.poc@example.test - transfer and beneficiary APIs
- ISG - Security POC - isg.poc@example.test - security evidence review
- EA - Architect POC - ea.poc@example.test - architecture signoff

FS / Requirement Summary:
Customer can add beneficiary, complete cooling period, and submit transfer with OTP confirmation. Flow impacts mobile UI, transfer API, beneficiary API, notifications, logs, and audit trail.

Open Issues / Risks:
- Transfer API timeout behavior needs confirmation from Payments API team.
- ISG evidence pending for SAST, SCA, secret scan, and log masking.
- EA needs data flow and downstream dependency confirmation.

ISG Evidence Available:
Unit test evidence available. SAST, SCA, secret scan, API security, TLS pinning, secure storage, and log masking evidence pending.
