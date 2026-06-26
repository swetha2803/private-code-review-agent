# Private Code Review Desk

Static, browser-only code review and security scanning page for sensitive source code.

## Privacy

- No backend.
- No CDN.
- No analytics.
- No network upload code path.
- Files are read with the browser `FileReader` API on the local machine.
- Reports are generated locally as JSON.
- Review packs are generated locally for security testing, unit testing, ISG testing, and dummy test data.
- Release gates, vendor evidence requests, manual review prompts, abuse cases, and Markdown reports are generated locally.

This tool can be hosted publicly because only the app shell is public. Reviewed code stays on the reviewer's device.

## Bank-Grade Review Model

For vendor banking code, use this app as your private review desk and run recognized scanners locally or inside your company network.

Recommended local scanner set:

- Semgrep for SAST.
- Gitleaks for secrets.
- OWASP Dependency-Check for vulnerable dependencies.
- SonarQube or Sonar Scanner when your organization has an approved SonarQube server.
- CodeQL, Checkmarx, Fortify, or Veracode only when approved by your bank/company process.

This repository includes `tools/run-security-review.ps1`, which runs installed local scanners and writes reports into `reports/`.

It also includes a local review agent:

```powershell
npm run agent -- "C:\path\to\vendor\source"
```

The agent recursively scans reviewable files, generates JSON and Markdown reports, creates evidence requests, produces security/unit/manual/abuse test packs, and exits with a non-zero code when critical or high findings exist.

Integration lead features:

- API inventory extracted from source patterns.
- Reviewed API report with risk focus for transfer, payment, beneficiary, login, OTP, profile, account, and statement APIs.
- Sanitized log analyzer for secrets, PII, stack traces, auth failures, and timeout/integration instability.
- Copy-ready vendor message, API team message, and log follow-up message.
- Meeting agenda/status summary in generated reports.
- Offline browser workbench for FS review, tracker row generation, CR readiness, EA/ISG signoff checklist, status mail, issue fixing mail, and Gamma-ready deck outline.

Do not paste real customer data, tokens, OTPs, passwords, production secrets, or unmasked banking identifiers into logs or reports.

Run the agent's own tests:

```powershell
npm test
```

Example:

```powershell
.\tools\run-security-review.ps1 -SourcePath "C:\path\to\vendor\source"
```

Then open `index.html` and import the generated Semgrep, Gitleaks, or SARIF report.

The page also generates a review decision:

- `Reject` when critical findings exist.
- `Hold` when high findings exist.
- `Needs review` when medium findings are excessive.
- `Conditional` when only lower-risk findings exist.
- `No blocking findings` when the current result set is clean.

Use the generated Markdown report as a vendor review working paper. Do not treat a clean heuristic result as production approval without scanner evidence and manual review.

Optional custom Semgrep banking rules are in `scanner-config/semgrep-banking.yml`:

```powershell
semgrep scan --config .\scanner-config\semgrep-banking.yml --json --output .\reports\semgrep-banking.json "C:\path\to\vendor\source"
```

## Usage

Open `index.html` in a browser, then paste code or upload files/folders.

For offline installation behavior, serve it once from any static host or local HTTP server so the service worker can cache the files. After that, the page can continue to load without internet.

## Free Hosting Options

- GitHub Pages
- Cloudflare Pages
- Netlify
- Vercel static project

Do not add server-side upload, logging, analytics, or AI APIs if the reviewed code is banking or confidential.

## Limits

This is a private review desk, report viewer, and offline checklist generator. It intentionally does not claim to be SonarQube, Fortify, Checkmarx, or CodeQL. Those tools perform deeper analysis that a free static browser page cannot fully reproduce. Formal acceptance should come from your bank/company-approved SAST, SCA, secret scanning, dependency review, penetration testing, and secure architecture review process.
