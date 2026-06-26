const state = {
  files: [],
  findings: [],
  filter: "all",
  reviewPack: null,
};

const elements = {
  fileInput: document.querySelector("#fileInput"),
  dropzone: document.querySelector("#dropzone"),
  codeInput: document.querySelector("#codeInput"),
  languageHint: document.querySelector("#languageHint"),
  scanBtn: document.querySelector("#scanBtn"),
  clearBtn: document.querySelector("#clearBtn"),
  downloadBtn: document.querySelector("#downloadBtn"),
  downloadPackBtn: document.querySelector("#downloadPackBtn"),
  downloadMarkdownBtn: document.querySelector("#downloadMarkdownBtn"),
  reportInput: document.querySelector("#reportInput"),
  findingsList: document.querySelector("#findingsList"),
  securityTestsList: document.querySelector("#securityTestsList"),
  unitTestsList: document.querySelector("#unitTestsList"),
  isgTestsList: document.querySelector("#isgTestsList"),
  dummyTestsList: document.querySelector("#dummyTestsList"),
  evidenceList: document.querySelector("#evidenceList"),
  manualReviewList: document.querySelector("#manualReviewList"),
  abuseCasesList: document.querySelector("#abuseCasesList"),
  releaseGatesList: document.querySelector("#releaseGatesList"),
  gateDecision: document.querySelector("#gateDecision"),
  riskScore: document.querySelector("#riskScore"),
  evidenceCount: document.querySelector("#evidenceCount"),
  manualCount: document.querySelector("#manualCount"),
  summaryText: document.querySelector("#summaryText"),
  criticalCount: document.querySelector("#criticalCount"),
  highCount: document.querySelector("#highCount"),
  mediumCount: document.querySelector("#mediumCount"),
  lowCount: document.querySelector("#lowCount"),
  privacyStatus: document.querySelector("#privacyStatus"),
  filterButtons: document.querySelectorAll(".filter-btn"),
};

const allowedExtensions = new Set([
  "js",
  "jsx",
  "ts",
  "tsx",
  "json",
  "yml",
  "yaml",
  "java",
  "kt",
  "kts",
  "swift",
  "xml",
  "gradle",
  "properties",
  "env",
  "md",
  "txt",
]);

const rules = [
  {
    id: "hardcoded-secret",
    title: "Possible hardcoded secret",
    severity: "critical",
    pattern:
      /\b(api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{12,})/i,
    description:
      "Credentials or long-lived secrets must not be committed in source code.",
    fix: "Move secrets to approved vault storage or secure build-time configuration. Rotate exposed values.",
  },
  {
    id: "private-key",
    title: "Private key material detected",
    severity: "critical",
    pattern: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/i,
    description: "Private key material in source code is a direct compromise risk.",
    fix: "Remove the key, rotate it, and use a managed key store.",
  },
  {
    id: "jwt",
    title: "JWT-like token detected",
    severity: "high",
    pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
    description: "JWTs can expose claims, sessions, or signing mistakes when committed.",
    fix: "Remove the token and verify that no live credential was committed.",
  },
  {
    id: "http-url",
    title: "Insecure HTTP endpoint",
    severity: "high",
    pattern: /http:\/\/(?!localhost|127\.0\.0\.1)[^\s"'<>]+/i,
    description: "Banking apps should avoid cleartext network transport.",
    fix: "Use HTTPS and enforce platform network security policies.",
  },
  {
    id: "tls-disabled",
    title: "TLS or certificate validation appears disabled",
    severity: "critical",
    pattern:
      /(rejectUnauthorized\s*:\s*false|TrustAll|HostnameVerifier|allowAllHostnameVerifier|NSAllowsArbitraryLoads\s*[:=]\s*true)/i,
    description: "Disabling TLS validation enables man-in-the-middle attacks.",
    fix: "Restore certificate validation and use certificate pinning where required by policy.",
  },
  {
    id: "console-log",
    title: "Runtime logging may expose sensitive data",
    severity: "medium",
    pattern: /\b(console\.(log|warn|error|debug)|Log\.(d|i|w|e)|print\s*\()/,
    description: "Logs in banking apps can leak account, session, or identity data.",
    fix: "Remove debug logging or route through a redacting approved logger.",
  },
  {
    id: "async-storage-sensitive",
    title: "Sensitive mobile data may use insecure storage",
    severity: "high",
    pattern: /(AsyncStorage|localStorage|SharedPreferences|UserDefaults).{0,80}(token|pin|password|account|session|secret)/i,
    description: "General local storage is not suitable for sensitive banking data.",
    fix: "Use Keychain, Keystore, encrypted storage, and short-lived session design.",
  },
  {
    id: "weak-crypto",
    title: "Weak or obsolete cryptography",
    severity: "high",
    pattern: /\b(MD5|SHA1|DES|3DES|RC4|ECB|PKCS1Padding)\b/i,
    description: "Weak algorithms and modes may fail banking security requirements.",
    fix: "Use approved modern algorithms and modes, such as AES-GCM and SHA-256 or stronger.",
  },
  {
    id: "eval",
    title: "Dynamic code execution",
    severity: "high",
    pattern: /\b(eval|new Function|setTimeout\s*\(\s*["'`]|setInterval\s*\(\s*["'`])\b/,
    description: "Dynamic execution increases injection and tampering risk.",
    fix: "Replace dynamic execution with explicit parsing and allowlisted behavior.",
  },
  {
    id: "sql-concat",
    title: "Possible SQL string concatenation",
    severity: "high",
    pattern:
      /(SELECT|INSERT|UPDATE|DELETE).{0,120}(\+|\$\{).{0,120}(where|values|from|into)/i,
    description: "String-built SQL can introduce injection vulnerabilities.",
    fix: "Use parameterized queries or approved query builders.",
  },
  {
    id: "debug-enabled",
    title: "Debug mode or development flag enabled",
    severity: "medium",
    pattern: /\b(debuggable\s+true|DEBUG\s*=\s*true|__DEV__\s*===?\s*true|devMode\s*[:=]\s*true)\b/i,
    description: "Debug behavior can expose internals in production builds.",
    fix: "Ensure release builds disable debugging and developer-only behavior.",
  },
  {
    id: "todo-security",
    title: "Security-sensitive TODO or FIXME",
    severity: "low",
    pattern: /(TODO|FIXME|HACK).{0,100}(security|auth|encrypt|token|password|temporary|bypass)/i,
    description: "Security-sensitive temporary workarounds need explicit tracking.",
    fix: "Convert the comment into a tracked issue and remove risky temporary logic before release.",
  },
  {
    id: "auth-bypass",
    title: "Possible authentication or authorization bypass",
    severity: "critical",
    pattern: /(bypass|skip|disable|mock).{0,60}(auth|authorization|login|otp|mfa|biometric)/i,
    description: "Bypass logic in authentication or authorization paths is high risk for banking apps.",
    fix: "Remove bypass behavior from production code and require explicit test-only guards.",
  },
  {
    id: "pii-in-code",
    title: "Possible PII or banking identifier exposure",
    severity: "high",
    pattern: /(accountNumber|customerId|cif|pan|iban|aadhaar|ssn|dateOfBirth|dob).{0,80}(["'`]|console|Log\.|print)/i,
    description: "PII and banking identifiers must not be exposed in logs, fixtures, or hardcoded values.",
    fix: "Mask or tokenize sensitive values and use approved dummy data in tests.",
  },
  {
    id: "otp-weakness",
    title: "OTP or MFA handling needs review",
    severity: "high",
    pattern: /(otp|mfa|oneTimePassword).{0,120}(hardcode|default|123456|000000|autoFill|clipboard|log|console)/i,
    description: "OTP/MFA flows are sensitive and need strict handling against leakage and replay.",
    fix: "Block hardcoded OTPs, avoid clipboard/log exposure, and verify expiry, retry, and lockout controls.",
  },
  {
    id: "webview-risk",
    title: "Risky WebView configuration",
    severity: "high",
    pattern: /(javaScriptEnabled\s*[:=]\s*true|setJavaScriptEnabled\s*\(\s*true|allowFileAccess\s*[:=]\s*true|setAllowFileAccess\s*\(\s*true|originWhitelist\s*=\s*\{\s*\[\s*['\"]\*['\"])/i,
    description: "WebView settings can expose banking apps to injection, file access, and origin abuse.",
    fix: "Restrict origins, disable file access unless required, and use hardened WebView policies.",
  },
  {
    id: "biometric-fallback",
    title: "Biometric fallback requires control review",
    severity: "medium",
    pattern: /(biometric|faceId|touchId|LocalAuthentication).{0,120}(fallback|passcode|skip|cancel)/i,
    description: "Biometric fallback behavior must be reviewed for account takeover risk.",
    fix: "Verify fallback policy, session binding, retry limits, and step-up authentication requirements.",
  },
  {
    id: "root-jailbreak-missing",
    title: "Root or jailbreak control appears bypassable",
    severity: "medium",
    pattern: /(rooted|jailbreak|tamper|frida|magisk).{0,120}(false|skip|bypass|disable|mock)/i,
    description: "Tamper/root/jailbreak controls must not be bypassable in production builds.",
    fix: "Require release-only enforcement and verify behavior on rooted, jailbroken, and instrumented devices.",
  },
  {
    id: "insecure-random",
    title: "Insecure randomness",
    severity: "high",
    pattern: /\b(Math\.random|Random\(|arc4random\(|java\.util\.Random)\b/,
    description: "Security-sensitive tokens, nonces, and OTP values require cryptographically secure randomness.",
    fix: "Use SecureRandom, crypto.getRandomValues, SecRandomCopyBytes, or an approved crypto provider.",
  },
  {
    id: "excessive-permission",
    title: "Sensitive mobile permission requires justification",
    severity: "medium",
    pattern: /(READ_SMS|RECEIVE_SMS|READ_CONTACTS|READ_CALL_LOG|ACCESS_FINE_LOCATION|RECORD_AUDIO|CAMERA)/,
    description: "Sensitive permissions in banking apps require business justification and privacy review.",
    fix: "Minimize permissions and document purpose, consent, retention, and fallback behavior.",
  },
  {
    id: "insecure-cookie",
    title: "Cookie security attributes may be missing",
    severity: "high",
    pattern: /Set-Cookie(?!.*HttpOnly)(?!.*Secure)(?!.*SameSite)/i,
    description: "Session cookies need Secure, HttpOnly, and SameSite controls.",
    fix: "Set Secure, HttpOnly, SameSite, path, domain, and expiry according to policy.",
  },
  {
    id: "dependency-risk",
    title: "Dependency override or dynamic version",
    severity: "medium",
    pattern: /(resolutionStrategy|force\s+["']|latest\.release|\+["']|changing\s*=\s*true)/i,
    description: "Dynamic or forced dependency resolution can hide vulnerable or unreviewed packages.",
    fix: "Pin approved versions and require SCA evidence for every third-party dependency.",
  },
  {
    id: "android-exported",
    title: "Android exported component needs review",
    severity: "high",
    pattern: /android:exported\s*=\s*["']true["']/i,
    description: "Exported Android components may expose privileged screens, receivers, or services.",
    fix: "Set exported=false unless required and enforce permissions, auth checks, and intent validation.",
  },
  {
    id: "android-backup-enabled",
    title: "Android backup may expose app data",
    severity: "high",
    pattern: /android:allowBackup\s*=\s*["']true["']/i,
    description: "Device backup can expose local banking data if not explicitly controlled.",
    fix: "Disable backup for sensitive apps or define approved backup exclusions.",
  },
  {
    id: "screenshot-risk",
    title: "Sensitive screen capture protection may be missing",
    severity: "medium",
    pattern: /(FLAG_SECURE|isScreenCaptureEnabled|UIScreenCapturedDidChange|screenCapture).{0,120}(false|disable|remove|TODO|FIXME)/i,
    description: "Sensitive banking screens should block screenshots or react to screen recording where policy requires.",
    fix: "Enable screenshot/screen-recording controls on sensitive flows and test platform behavior.",
  },
  {
    id: "clipboard-sensitive",
    title: "Sensitive clipboard usage",
    severity: "high",
    pattern: /(Clipboard|UIPasteboard|setString|setPrimaryClip).{0,100}(otp|token|password|pin|account|card)/i,
    description: "Clipboard content can leak to other apps or system surfaces.",
    fix: "Avoid copying sensitive values or clear clipboard quickly with explicit user consent.",
  },
  {
    id: "deep-link-risk",
    title: "Deep link or URL scheme requires auth validation",
    severity: "medium",
    pattern: /(intent-filter|CFBundleURLSchemes|Linking\.addEventListener|openURL|handleOpenURL|deepLink|deeplink)/i,
    description: "Deep links can bypass expected navigation and authorization checks.",
    fix: "Validate destination, require session checks, reject untrusted parameters, and test unauthenticated links.",
  },
  {
    id: "unsafe-deserialization",
    title: "Unsafe deserialization pattern",
    severity: "critical",
    pattern: /(ObjectInputStream|readObject\(|pickle\.loads|yaml\.load\(|JSON\.parse\().{0,120}(request|input|payload|body|params)/i,
    description: "Deserializing untrusted input can lead to injection, crashes, or object abuse.",
    fix: "Use strict schemas, safe parsers, allowlists, and reject unknown fields.",
  },
  {
    id: "command-injection",
    title: "Possible command execution from input",
    severity: "critical",
    pattern: /(exec|spawn|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|system\().{0,120}(input|request|param|body|command)/i,
    description: "Shell or process execution with untrusted data can lead to command injection.",
    fix: "Remove shell execution, use fixed allowlisted commands, and separate arguments safely.",
  },
  {
    id: "path-traversal",
    title: "Possible path traversal risk",
    severity: "high",
    pattern: /(readFile|writeFile|File\(|Paths\.get|path\.join).{0,120}(request|param|input|filename|fileName|path)/i,
    description: "File paths built from input may allow unauthorized file access.",
    fix: "Normalize paths, reject traversal sequences, and constrain access to an allowlisted directory.",
  },
  {
    id: "cors-wide-open",
    title: "Wide-open CORS",
    severity: "high",
    pattern: /(Access-Control-Allow-Origin|cors\().{0,80}(\*|origin\s*:\s*true)/i,
    description: "Overly broad CORS can expose APIs or session data to untrusted origins.",
    fix: "Allow only approved origins and avoid credentialed wildcard CORS.",
  },
  {
    id: "rate-limit-missing-marker",
    title: "Sensitive endpoint may need rate limiting",
    severity: "medium",
    pattern: /(login|otp|mfa|password|pin|beneficiary|transfer).{0,120}(endpoint|route|api|mutation|request)/i,
    description: "Sensitive banking flows require brute-force, replay, and abuse controls.",
    fix: "Verify rate limits, lockouts, replay protection, idempotency, and fraud monitoring.",
  },
  {
    id: "pinning-bypass",
    title: "Certificate pinning bypass pattern",
    severity: "critical",
    pattern: /(pinning|certificatePinner|sslPinning|TrustKit).{0,120}(disable|bypass|false|debug|mock)/i,
    description: "Pinning bypass in production undermines transport security controls.",
    fix: "Ensure pinning bypass is impossible in release builds and covered by tests.",
  },
  {
    id: "analytics-sensitive",
    title: "Sensitive data may enter analytics or crash reporting",
    severity: "high",
    pattern: /(analytics|firebase|crashlytics|appcenter|sentry|datadog|newrelic).{0,120}(account|card|pan|token|password|otp|pin|customer)/i,
    description: "Telemetry and crash tools must not receive customer, account, credential, or session data.",
    fix: "Redact event properties, disable sensitive breadcrumbs, and document telemetry data classification.",
  },
  {
    id: "test-only-code",
    title: "Test-only code may be present in production path",
    severity: "medium",
    pattern: /(mock|stub|fake|dummy|sandbox).{0,100}(payment|transfer|auth|otp|login|account|beneficiary)/i,
    description: "Mock banking flows can accidentally ship or bypass real controls.",
    fix: "Fence test-only code behind build-time exclusions and verify release artifact contents.",
  },
];

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker
      .register("service-worker.js")
      .then(() => {
        elements.privacyStatus.textContent = "Offline-ready";
      })
      .catch(() => {
        elements.privacyStatus.textContent = "Local-only";
      });
  });
}

elements.fileInput.addEventListener("change", async (event) => {
  await loadFiles(Array.from(event.target.files || []));
});

["dragenter", "dragover"].forEach((eventName) => {
  elements.dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    elements.dropzone.classList.add("dragover");
  });
});

["dragleave", "drop"].forEach((eventName) => {
  elements.dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    elements.dropzone.classList.remove("dragover");
  });
});

elements.dropzone.addEventListener("drop", async (event) => {
  await loadFiles(Array.from(event.dataTransfer.files || []));
});

elements.scanBtn.addEventListener("click", runReview);
elements.clearBtn.addEventListener("click", clearAll);
elements.downloadBtn.addEventListener("click", downloadReport);
elements.downloadPackBtn.addEventListener("click", downloadReviewPack);
elements.downloadMarkdownBtn.addEventListener("click", downloadMarkdownReport);
elements.reportInput.addEventListener("change", importScannerReport);

elements.filterButtons.forEach((button) => {
  button.addEventListener("click", () => {
    state.filter = button.dataset.filter;
    elements.filterButtons.forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    renderFindings();
  });
});

renderReviewPack();

async function loadFiles(files) {
  const readableFiles = files.filter((file) => {
    const extension = getExtension(file.name);
    return allowedExtensions.has(extension) || file.type.startsWith("text/");
  });

  const loaded = await Promise.all(
    readableFiles.map(
      (file) =>
        new Promise((resolve) => {
          const reader = new FileReader();
          reader.onload = () => {
            resolve({
              name: file.webkitRelativePath || file.name,
              content: String(reader.result || ""),
            });
          };
          reader.onerror = () => resolve(null);
          reader.readAsText(file);
        }),
    ),
  );

  state.files = loaded.filter(Boolean);
  elements.summaryText.textContent = `${state.files.length} file(s) loaded locally.`;
}

function runReview() {
  const pasted = elements.codeInput.value.trim();
  const sources = [...state.files];

  if (pasted) {
    sources.push({
      name: `pasted-code.${hintToExtension(elements.languageHint.value)}`,
      content: pasted,
    });
  }

  if (!sources.length) {
    state.findings = [];
    state.reviewPack = null;
    renderSummary();
    renderFindings();
    renderReviewPack();
    return;
  }

  state.findings = sources.flatMap((file) => scanSource(file));
  state.reviewPack = buildReviewPack(state.findings, sources);
  renderSummary(sources.length);
  renderFindings();
  renderReviewPack();
}

function scanSource(file) {
  const findings = [];
  const lines = file.content.split(/\r?\n/);

  lines.forEach((line, index) => {
    rules.forEach((rule) => {
      if (rule.pattern.test(line)) {
        findings.push({
          id: rule.id,
          title: rule.title,
          severity: rule.severity,
          description: rule.description,
          fix: rule.fix,
          file: file.name,
          line: index + 1,
          snippet: line.trim().slice(0, 360),
        });
      }
    });
  });

  findings.push(...reviewFileShape(file, lines));
  return findings;
}

function reviewFileShape(file, lines) {
  const findings = [];
  const extension = getExtension(file.name);
  const content = lines.join("\n");

  if ((extension === "js" || extension === "ts" || extension === "tsx") && lines.length > 700) {
    findings.push({
      id: "large-file",
      title: "Large source file",
      severity: "low",
      description: "Large files are harder to review and test thoroughly.",
      fix: "Split unrelated responsibilities and add focused tests around sensitive flows.",
      file: file.name,
      line: 1,
      snippet: `${lines.length} lines`,
    });
  }

  if (/axios|fetch\s*\(/.test(content) && !/timeout\s*:|AbortController/.test(content)) {
    findings.push({
      id: "network-timeout",
      title: "Network call may lack timeout handling",
      severity: "medium",
      description: "Mobile banking flows need bounded network behavior and clear failure states.",
      fix: "Add request timeout, cancellation, retry policy, and auditable error handling.",
      file: file.name,
      line: findLine(lines, /axios|fetch\s*\(/),
      snippet: "Network request detected without obvious timeout or cancellation.",
    });
  }

  if (/password|pin|otp|token/i.test(content) && !/mask|redact|secureTextEntry|obscure/i.test(content)) {
    findings.push({
      id: "sensitive-ui-masking",
      title: "Sensitive input may not be masked or redacted",
      severity: "medium",
      description: "Credentials, OTPs, and tokens should not be visible or logged accidentally.",
      fix: "Use secure input controls and redact sensitive values in errors, state, and telemetry.",
      file: file.name,
      line: findLine(lines, /password|pin|otp|token/i),
      snippet: "Sensitive keyword found without nearby masking or redaction pattern.",
    });
  }

  return findings;
}

function renderSummary(fileCount = state.files.length + (elements.codeInput.value.trim() ? 1 : 0)) {
  const counts = countBySeverity(state.findings);
  elements.criticalCount.textContent = counts.critical;
  elements.highCount.textContent = counts.high;
  elements.mediumCount.textContent = counts.medium;
  elements.lowCount.textContent = counts.low;

  const total = state.findings.length;
  elements.summaryText.textContent = total
    ? `${total} finding(s) across ${fileCount} source item(s).`
    : `${fileCount} source item(s) reviewed. No matching issues found.`;
  elements.downloadBtn.disabled = total === 0;
}

function renderFindings() {
  const visible =
    state.filter === "all"
      ? state.findings
      : state.findings.filter((finding) => finding.severity === state.filter);

  if (!visible.length) {
    elements.findingsList.innerHTML = `<div class="empty-state">No findings for this filter.</div>`;
    return;
  }

  elements.findingsList.innerHTML = visible
    .map(
      (finding) => `
        <article class="finding ${escapeHtml(finding.severity)}">
          <div class="finding-head">
            <div class="finding-title">${escapeHtml(finding.title)}</div>
            <span class="severity ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
          </div>
          <div class="finding-meta">${escapeHtml(finding.file)}:${finding.line} - ${escapeHtml(finding.id)}</div>
          <div class="finding-desc">${escapeHtml(finding.description)}</div>
          <div class="finding-fix"><strong>Fix:</strong> ${escapeHtml(finding.fix)}</div>
          <pre class="finding-code"><code>${escapeHtml(finding.snippet)}</code></pre>
        </article>
      `,
    )
    .join("");
}

function downloadReport() {
  const report = {
    generatedAt: new Date().toISOString(),
    privacy: "Generated locally in the browser. Source code was not uploaded by this static app.",
    summary: countBySeverity(state.findings),
    findings: state.findings,
    reviewPack: state.reviewPack,
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `private-code-review-${new Date().toISOString().slice(0, 10)}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

async function importScannerReport(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) return;

  const text = await file.text();
  let parsed;

  try {
    parsed = JSON.parse(text);
  } catch {
    elements.summaryText.textContent = "Report import failed. The file is not valid JSON or SARIF.";
    return;
  }

  const imported = normalizeScannerReport(parsed, file.name);
  state.findings = imported;
  state.reviewPack = buildReviewPack(state.findings, []);
  state.filter = "all";
  elements.filterButtons.forEach((item) => {
    item.classList.toggle("active", item.dataset.filter === "all");
  });
  renderSummary(1);
  renderFindings();
  renderReviewPack();
  elements.reportInput.value = "";
}

function buildReviewPack(findings, sources) {
  const ids = new Set(findings.map((finding) => finding.id));
  const sourceText = sources.map((source) => source.content).join("\n").toLowerCase();
  const fileNames = sources.map((source) => source.name.toLowerCase()).join("\n");
  const counts = countBySeverity(findings);
  const riskScore = counts.critical * 40 + counts.high * 15 + counts.medium * 5 + counts.low;
  const decision =
    counts.critical > 0
      ? "Reject"
      : counts.high > 0
        ? "Hold"
        : counts.medium > 5
          ? "Needs review"
          : findings.length
            ? "Conditional"
            : "No blocking findings";

  return {
    generatedAt: new Date().toISOString(),
    decision,
    riskScore,
    counts,
    securityTests: uniqueItems([
      "Run SAST with Semgrep or CodeQL and require zero critical/high findings before acceptance.",
      "Run secret scanning with Gitleaks and require vendor attestation for every rotated/remediated secret.",
      "Run dependency/SCA scan and require CVE remediation or risk acceptance for vulnerable packages.",
      "Verify release build blocks debug flags, mock endpoints, test OTPs, and bypass switches.",
      "Run mobile DAST/proxy testing for login, OTP, beneficiary, transfer, profile, and statement flows.",
      "Run API negative testing for authZ, replay, idempotency, tampering, rate limits, and error leakage.",
      "Run device tests on clean, rooted/jailbroken, debug-proxy, clock-changed, and offline devices.",
      ids.has("http-url") && "Attempt traffic interception and verify all non-local traffic uses HTTPS only.",
      ids.has("tls-disabled") && "Perform MITM test and verify certificate validation cannot be bypassed.",
      ids.has("webview-risk") && "Test WebView origin restrictions, JavaScript exposure, file access, and deep-link abuse.",
      ids.has("async-storage-sensitive") && "Inspect device storage and backups for tokens, PINs, OTPs, and account data.",
      ids.has("otp-weakness") && "Test OTP expiry, retry limits, replay prevention, lockout, and log redaction.",
      ids.has("auth-bypass") && "Attempt direct navigation/API calls around login, MFA, and role checks.",
      ids.has("android-exported") && "Attempt to launch exported Android activities/services/receivers without app authentication.",
      ids.has("clipboard-sensitive") && "Verify sensitive clipboard values are not exposed to other apps or retained.",
      ids.has("pinning-bypass") && "Verify SSL pinning cannot be disabled in release builds.",
      ids.has("analytics-sensitive") && "Inspect telemetry/crash payloads for PII, account data, tokens, and OTPs.",
      /(biometric|faceid|touchid)/i.test(sourceText) &&
        "Test biometric fallback, cancellation, device enrollment changes, and session re-authentication.",
      /(root|jailbreak|frida|magisk)/i.test(sourceText) &&
        "Test rooted/jailbroken/instrumented device behavior and verify production blocking policy.",
    ]),
    unitTests: uniqueItems([
      "Add tests for success, failure, timeout, retry, and cancellation paths in network/service functions.",
      "Add tests proving sensitive errors are redacted before logging, telemetry, or UI display.",
      "Add tests for null, empty, malformed, oversized, and unexpected API response payloads.",
      "Add auth tests for expired session, revoked token, changed password, changed device, and concurrent login.",
      "Add authorization tests proving users cannot access another customer account, card, beneficiary, or transaction.",
      "Add transaction tests for duplicate submit, back button, app kill/resume, timeout after debit, and retry after pending status.",
      "Add form validation tests for amount precision, currency mismatch, beneficiary limits, and daily/monthly limits.",
      "Add error mapping tests so server errors never expose stack traces, internal codes, or sensitive payloads.",
      ids.has("sensitive-ui-masking") && "Add UI tests proving PIN, password, OTP, and token fields are masked.",
      ids.has("network-timeout") && "Add unit tests for request timeout and abort behavior.",
      ids.has("weak-crypto") && "Add tests that reject weak algorithms and accept only approved crypto configuration.",
      ids.has("sql-concat") && "Add tests proving query inputs are parameterized and injection payloads are not executable.",
      ids.has("insecure-random") && "Add tests or code review evidence proving secure random APIs generate tokens/nonces.",
      ids.has("deep-link-risk") && "Add tests proving deep links cannot open protected screens without re-authentication.",
      /(redux|zustand|context|state)/i.test(sourceText) &&
        "Add state-management tests proving logout clears sensitive cached state.",
      /(navigation|router|deeplink|linking)/i.test(sourceText) &&
        "Add navigation tests proving protected screens require an authenticated session.",
    ]),
    isgTests: uniqueItems([
      "Confirm vendor provides SAST, SCA, secret scan, unit test, and release build evidence.",
      "Confirm no production credentials, internal URLs, certificates, or private keys are present in source.",
      "Confirm sensitive data classification, masking, logging, retention, and deletion are documented.",
      "Confirm mobile platform controls: certificate pinning policy, secure storage, anti-tamper, obfuscation, and secure keyboard where applicable.",
      "Confirm dependency inventory includes package name, version, license, CVE status, and approval owner.",
      "Confirm API security evidence covers auth, authorization, replay, rate limits, input validation, and error handling.",
      "Confirm privacy review for permissions, analytics, crash reporting, and third-party SDKs.",
      "Confirm release gates block critical/high security findings unless formally risk accepted.",
      "Confirm threat model covers account takeover, transaction fraud, device compromise, API abuse, and privacy leakage.",
      "Confirm secure coding checklist is signed by vendor lead and internal reviewer.",
      "Confirm test evidence includes screenshots/log extracts with masked data and reproducible build number.",
      "Confirm open-source license review and dependency approval are complete.",
      "Confirm all security exceptions have owner, expiry date, compensating control, and business approver.",
      fileNames.includes("androidmanifest.xml") &&
        "Review AndroidManifest permissions, exported components, cleartext policy, backup policy, and intent filters.",
      fileNames.includes("info.plist") &&
        "Review iOS Info.plist transport security, URL schemes, privacy strings, and background modes.",
    ]),
    dummyTests: uniqueItems([
      "Use synthetic customer IDs, accounts, cards, names, phone numbers, emails, and addresses only.",
      "Use invalid, expired, locked, dormant, KYC-pending, and high-risk customer profiles.",
      "Use edge balances: zero, negative where domain allows, maximum limit, decimal precision, and currency mismatch.",
      "Use transaction cases for duplicate request, retry after timeout, pending status, reversal, and failed beneficiary validation.",
      "Use auth cases for wrong PIN, expired OTP, reused OTP, locked account, changed device, and session timeout.",
      "Use malformed API payloads with missing fields, extra fields, wrong types, long strings, and Unicode names.",
      "Use privacy-safe screenshots and logs with masked PAN/account numbers and no real customer data.",
      "Use role cases: retail user, corporate maker, corporate checker, admin-like support role, and unauthorized role.",
      "Use transfer cases: own account, registered beneficiary, new beneficiary cooling period, blocked beneficiary, and limit exceeded.",
      "Use device cases: first install, upgrade, reinstall, cleared storage, clock tamper, airplane mode, and VPN/proxy enabled.",
    ]),
    evidenceRequests: uniqueItems([
      "SAST report with rule set, scan date, commit hash, and zero unresolved critical/high issues.",
      "Secret scan report plus written confirmation that no real credentials are present.",
      "SCA/dependency report with CVE status, licenses, and remediation/risk acceptance for each finding.",
      "Unit test and coverage report for changed modules, including negative/security test names.",
      "Mobile manifest review evidence for Android and iOS security-sensitive settings.",
      "API contract, auth scheme, token lifetime, refresh flow, and error response documentation.",
      "Certificate pinning/TLS policy evidence and MITM test result.",
      "Secure storage evidence for tokens, PINs, biometrics, customer identifiers, and cached responses.",
      "Logging/telemetry data dictionary proving no PII, account, credential, OTP, or token leakage.",
      "Release build evidence showing debug disabled, minification/obfuscation enabled where applicable, and test code excluded.",
      "Pen test or security test summary for high-risk flows: login, OTP, transfer, beneficiary, profile, cards, statements.",
      "Vendor remediation sheet with finding ID, severity, fix commit, test proof, owner, and closure date.",
    ]),
    manualReview: uniqueItems([
      "Trace every login/session/token path manually from UI to API and logout.",
      "Trace every money movement path for authorization, confirmation, idempotency, and audit trail.",
      "Review whether UI hides server-side authorization gaps by relying only on disabled buttons or hidden screens.",
      "Review all config files for environment mix-ups, internal URLs, feature flags, and mock endpoints.",
      "Review error handling for stack traces, raw backend messages, account status leakage, and retry loops.",
      "Review state/cache clearing on logout, token expiry, app background, app kill, and device change.",
      "Review third-party SDKs for data collection, permissions, network calls, and initialization keys.",
      "Review accessibility and localization paths for accidental disclosure of hidden sensitive values.",
      "Review branch/build scripts for skipped tests, ignored scanner failures, or release signing shortcuts.",
      "Review all TODO/FIXME/HACK comments in auth, payment, crypto, storage, logging, and API code.",
    ]),
    abuseCases: uniqueItems([
      "Try replaying a successful transfer request with the same request ID and changed amount.",
      "Try changing customer/account/beneficiary IDs in API requests and deep-link parameters.",
      "Try submitting OTP after expiry, after successful use, and across different sessions/devices.",
      "Try app resume after token expiry, network timeout, pending transaction, and force close.",
      "Try proxy interception with user-installed CA, invalid cert, expired cert, and pinned cert mismatch.",
      "Try opening protected screens from deep links, push notifications, browser redirects, and app shortcuts.",
      "Try using rooted/jailbroken indicators, Frida hooks, emulator, tampered clock, and debug bridge.",
      "Try long strings, Unicode, script tags, SQL meta characters, path traversal strings, and JSON type confusion.",
      "Try copying screenshots, screen recordings, clipboard values, and notification previews on sensitive screens.",
      "Try downgrade/upgrade scenarios where old cached data or old tokens remain available.",
    ]),
    releaseGates: uniqueItems([
      counts.critical > 0
        ? "BLOCK: Critical findings must be fixed or formally risk accepted."
        : "PASS: No critical findings in current imported/local result set.",
      counts.high > 0
        ? "BLOCK/HOLD: High findings require remediation before production acceptance."
        : "PASS: No high findings in current imported/local result set.",
      "Require clean secret scan before accepting vendor delivery.",
      "Require dependency scan with no exploitable critical/high CVEs or approved exceptions.",
      "Require evidence for secure storage, TLS/certificate validation, logging redaction, and release build hardening.",
      "Require manual review completion for auth, payment, beneficiary, profile, and statement flows.",
      "Require retest evidence after every vendor remediation commit.",
    ]),
  };
}

function renderReviewPack() {
  const pasted = elements.codeInput.value.trim();
  const sources = state.files.length ? state.files : pasted ? [{ name: "pasted-code", content: pasted }] : [];
  const pack = state.reviewPack || buildReviewPack([], sources);

  renderList(elements.securityTestsList, pack.securityTests);
  renderList(elements.unitTestsList, pack.unitTests);
  renderList(elements.isgTestsList, pack.isgTests);
  renderList(elements.dummyTestsList, pack.dummyTests);
  renderList(elements.evidenceList, pack.evidenceRequests);
  renderList(elements.manualReviewList, pack.manualReview);
  renderList(elements.abuseCasesList, pack.abuseCases);
  renderList(elements.releaseGatesList, pack.releaseGates);
  elements.gateDecision.textContent = pack.decision;
  elements.riskScore.textContent = pack.riskScore;
  elements.evidenceCount.textContent = pack.evidenceRequests.length;
  elements.manualCount.textContent = pack.manualReview.length;
  elements.downloadPackBtn.disabled = !state.findings.length && !sources.length;
  elements.downloadMarkdownBtn.disabled = !state.findings.length && !sources.length;
}

function renderList(target, items) {
  target.innerHTML = items.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
}

function downloadReviewPack() {
  const pasted = elements.codeInput.value.trim();
  const sources = state.files.length ? state.files : pasted ? [{ name: "pasted-code", content: pasted }] : [];
  const pack = state.reviewPack || buildReviewPack(state.findings, sources);
  const blob = new Blob([JSON.stringify(pack, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `vendor-review-pack-${new Date().toISOString().slice(0, 10)}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

function downloadMarkdownReport() {
  const pasted = elements.codeInput.value.trim();
  const sources = state.files.length ? state.files : pasted ? [{ name: "pasted-code", content: pasted }] : [];
  const pack = state.reviewPack || buildReviewPack(state.findings, sources);
  const markdown = buildMarkdownReport(pack, state.findings);
  const blob = new Blob([markdown], {
    type: "text/markdown",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `vendor-security-review-${new Date().toISOString().slice(0, 10)}.md`;
  anchor.click();
  URL.revokeObjectURL(url);
}

function buildMarkdownReport(pack, findings) {
  const sections = [
    ["Security Testing", pack.securityTests],
    ["Unit Test Generation", pack.unitTests],
    ["ISG Testing", pack.isgTests],
    ["Dummy Testing Data", pack.dummyTests],
    ["Vendor Evidence", pack.evidenceRequests],
    ["Manual Review", pack.manualReview],
    ["Abuse Cases", pack.abuseCases],
    ["Release Gates", pack.releaseGates],
  ];

  return [
    "# Vendor Security Review",
    "",
    `Generated: ${pack.generatedAt}`,
    `Decision: ${pack.decision}`,
    `Risk score: ${pack.riskScore}`,
    `Findings: critical ${pack.counts.critical}, high ${pack.counts.high}, medium ${pack.counts.medium}, low ${pack.counts.low}`,
    "",
    "## Findings",
    findings.length
      ? findings
          .map(
            (finding) =>
              `- [${finding.severity.toUpperCase()}] ${finding.file}:${finding.line} ${finding.title} (${finding.id})`,
          )
          .join("\n")
      : "- No automated findings in the current result set.",
    "",
    ...sections.flatMap(([title, items]) => [
      `## ${title}`,
      ...items.map((item) => `- ${item}`),
      "",
    ]),
  ].join("\n");
}

function uniqueItems(items) {
  return [...new Set(items.filter(Boolean))];
}

function normalizeScannerReport(report, sourceName) {
  if (Array.isArray(report.findings)) {
    return report.findings.map((item) => ({
      id: item.id || "review-agent",
      title: item.title || "Review agent finding",
      severity: mapSeverity(item.severity),
      description: item.description || item.title || "Review agent detected an issue.",
      fix: item.fix || "Review and remediate before accepting vendor delivery.",
      file: item.file || sourceName,
      line: item.line || 1,
      snippet: item.snippet || "",
    }));
  }

  if (Array.isArray(report.results)) {
    return report.results.map((item) => normalizeSemgrepFinding(item, sourceName));
  }

  if (Array.isArray(report)) {
    return report.map((item) => normalizeGitleaksFinding(item, sourceName));
  }

  if (Array.isArray(report.runs)) {
    return normalizeSarifFindings(report, sourceName);
  }

  return [
    {
      id: "unknown-report",
      title: "Unsupported report format",
      severity: "low",
      description: "The report was valid JSON, but it did not match Semgrep, Gitleaks, or SARIF shapes.",
      fix: "Export scanner output as Semgrep JSON, Gitleaks JSON, or SARIF.",
      file: sourceName,
      line: 1,
      snippet: "No compatible findings were imported.",
    },
  ];
}

function normalizeSemgrepFinding(item, sourceName) {
  const severity = mapSeverity(item.extra && item.extra.severity);
  return {
    id: item.check_id || "semgrep",
    title: (item.extra && item.extra.message) || item.check_id || "Semgrep finding",
    severity,
    description: (item.extra && item.extra.message) || "Semgrep detected a security or quality issue.",
    fix: "Review the Semgrep rule guidance and remediate before accepting vendor delivery.",
    file: item.path || sourceName,
    line: (item.start && item.start.line) || 1,
    snippet: item.extra && item.extra.lines ? item.extra.lines.trim().slice(0, 360) : "",
  };
}

function normalizeGitleaksFinding(item, sourceName) {
  return {
    id: item.RuleID || "gitleaks",
    title: item.Description || "Secret detected",
    severity: "critical",
    description: "Gitleaks detected a possible secret or credential in the submitted code.",
    fix: "Remove the secret, rotate it, and require the vendor to explain exposure scope.",
    file: item.File || sourceName,
    line: item.StartLine || item.Line || 1,
    snippet: item.Secret ? String(item.Secret).slice(0, 12) + "..." : item.Match || "",
  };
}

function normalizeSarifFindings(report, sourceName) {
  return report.runs.flatMap((run) => {
    const rulesById = new Map(
      ((run.tool && run.tool.driver && run.tool.driver.rules) || []).map((rule) => [
        rule.id,
        rule,
      ]),
    );

    return (run.results || []).map((result) => {
      const rule = rulesById.get(result.ruleId) || {};
      const location = result.locations && result.locations[0];
      const physical = location && location.physicalLocation;
      const region = physical && physical.region;
      const artifact = physical && physical.artifactLocation;

      return {
        id: result.ruleId || "sarif",
        title:
          (result.message && result.message.text) ||
          rule.name ||
          result.ruleId ||
          "SARIF finding",
        severity: mapSarifSeverity(result, rule),
        description:
          (result.message && result.message.text) ||
          (rule.shortDescription && rule.shortDescription.text) ||
          "Imported SARIF scanner finding.",
        fix:
          (rule.help && rule.help.text) ||
          "Review the scanner guidance and remediate before accepting vendor delivery.",
        file: (artifact && artifact.uri) || sourceName,
        line: (region && region.startLine) || 1,
        snippet: "",
      };
    });
  });
}

function mapSeverity(value) {
  const normalized = String(value || "").toLowerCase();
  if (["error", "critical"].includes(normalized)) return "critical";
  if (["warning", "high"].includes(normalized)) return "high";
  if (["medium", "moderate"].includes(normalized)) return "medium";
  return "low";
}

function mapSarifSeverity(result, rule) {
  const level = result.level || (rule.defaultConfiguration && rule.defaultConfiguration.level);
  const securitySeverity =
    rule.properties && Number.parseFloat(rule.properties["security-severity"]);

  if (Number.isFinite(securitySeverity)) {
    if (securitySeverity >= 9) return "critical";
    if (securitySeverity >= 7) return "high";
    if (securitySeverity >= 4) return "medium";
    return "low";
  }

  return mapSeverity(level);
}

function clearAll() {
  state.files = [];
  state.findings = [];
  state.reviewPack = null;
  elements.fileInput.value = "";
  elements.codeInput.value = "";
  elements.downloadBtn.disabled = true;
  elements.downloadPackBtn.disabled = true;
  renderSummary(0);
  elements.findingsList.innerHTML = `<div class="empty-state">Upload a folder, upload files, or paste code to run a private review.</div>`;
  renderReviewPack();
}

function countBySeverity(findings) {
  return findings.reduce(
    (counts, finding) => {
      counts[finding.severity] += 1;
      return counts;
    },
    { critical: 0, high: 0, medium: 0, low: 0 },
  );
}

function getExtension(fileName) {
  const normalized = fileName.toLowerCase();
  if (normalized.endsWith(".gradle")) return "gradle";
  if (normalized.endsWith(".env")) return "env";
  const last = normalized.split(".").pop();
  return last || "";
}

function hintToExtension(hint) {
  const map = {
    js: "js",
    "react-native": "tsx",
    java: "kt",
    swift: "swift",
    config: "json",
    auto: "txt",
  };
  return map[hint] || "txt";
}

function findLine(lines, pattern) {
  const index = lines.findIndex((line) => pattern.test(line));
  return index >= 0 ? index + 1 : 1;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
