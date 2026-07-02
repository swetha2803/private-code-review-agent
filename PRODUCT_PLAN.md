# Integration Review Command Center - Product Plan

## Purpose

This tool is a private offline workbench for integration leads who need to review vendor delivery, code, APIs, logs, FS/LLD, CR readiness, EA signoff, ISG readiness, and communication without uploading sensitive code or data.

## Security Model

- No backend.
- No analytics.
- No CDN.
- No AI API calls.
- No email sending.
- No Gamma/cloud integration.
- Browser dashboard works offline.
- Local agent scans folders or ZIP files on the user's machine.
- Reports are generated locally.

## Current Capabilities

- Browser-only dashboard.
- Local Node.js review agent.
- Folder scan.
- ZIP scan.
- Code/security rules.
- Java, mobile, backend, frontend, generic review support.
- API inventory extraction.
- Application flow explanation.
- Log analyzer.
- FS review support.
- Tracker row generation.
- Tracker CSV export.
- CR readiness checklist.
- EA template generator.
- ISG pre-assessment.
- LLD and evidence validation.
- Claim-vs-evidence validation.
- Review profiles: Generic, Mobile, Backend, Frontend, Integration, Full stack.
- Local session save/load.
- Session JSON import/export.
- Mail draft generation.
- Gamma-ready outline export.
- Offline review assistant for plain-English explanation, next actions, vendor questions, internal-team questions, and clarification mail.
- Technical and functional explanation assistant for users returning to code review after a long gap.
- Redaction helper and issue register for safer communication and structured closure tracking.
- Printable report view for manager, EA, ISG, vendor, or audit-style sharing.
- Optional online research mode for generic references only, controlled by an explicit toggle.
- Sample project and sample validation script.

## Recommended Next Improvements

1. Real template import for EA, ISG, CR, tracker, and mail formats.
2. Issue register with owner, ETA, RCA, fix version, retest status, and closure status.
3. Redaction helper for logs and reports.
4. Printable/PDF-ready executive report page.
5. Checklist item statuses: Pending, Done, Waived, Not Applicable.
6. Custom review rules from the browser UI.
7. POC/application dependency matrix.
8. Multiple saved sessions list, not only latest session.
9. Evidence register for SAST, SCA, secret scan, UAT, deployment, rollback, and signoff files.
10. Optional internal-only deployment package for bank VPN/intranet.

## Important Limitation

This is a review assistant and evidence organizer. It does not replace approved bank tools such as SonarQube, Checkmarx, Fortify, CodeQL, Semgrep Enterprise, SCA tools, VA/PT, or formal ISG/EA approval.
