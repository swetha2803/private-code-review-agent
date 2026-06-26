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
  logInput: document.querySelector("#logInput"),
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
  apiInventoryList: document.querySelector("#apiInventoryList"),
  applicationFlowList: document.querySelector("#applicationFlowList"),
  logAnalysisList: document.querySelector("#logAnalysisList"),
  vendorMessage: document.querySelector("#vendorMessage"),
  apiMessage: document.querySelector("#apiMessage"),
  logMessage: document.querySelector("#logMessage"),
  generateWorkbenchBtn: document.querySelector("#generateWorkbenchBtn"),
  exportWorkbenchBtn: document.querySelector("#exportWorkbenchBtn"),
  wbAppName: document.querySelector("#wbAppName"),
  wbDevTitle: document.querySelector("#wbDevTitle"),
  wbEnvironment: document.querySelector("#wbEnvironment"),
  wbPlatform: document.querySelector("#wbPlatform"),
  wbPocs: document.querySelector("#wbPocs"),
  wbFsSummary: document.querySelector("#wbFsSummary"),
  wbIssues: document.querySelector("#wbIssues"),
  trackerOutput: document.querySelector("#trackerOutput"),
  fsReviewOutput: document.querySelector("#fsReviewOutput"),
  crReadinessOutput: document.querySelector("#crReadinessOutput"),
  signoffOutput: document.querySelector("#signoffOutput"),
  statusMailOutput: document.querySelector("#statusMailOutput"),
  issueMailOutput: document.querySelector("#issueMailOutput"),
  gammaOutput: document.querySelector("#gammaOutput"),
  generateSignoffBtn: document.querySelector("#generateSignoffBtn"),
  exportSignoffBtn: document.querySelector("#exportSignoffBtn"),
  eaPattern: document.querySelector("#eaPattern"),
  dataClassification: document.querySelector("#dataClassification"),
  internetFacing: document.querySelector("#internetFacing"),
  piiInvolved: document.querySelector("#piiInvolved"),
  eaDataFlow: document.querySelector("#eaDataFlow"),
  eaDependencies: document.querySelector("#eaDependencies"),
  isgEvidence: document.querySelector("#isgEvidence"),
  securityExceptions: document.querySelector("#securityExceptions"),
  isgDecision: document.querySelector("#isgDecision"),
  isgScore: document.querySelector("#isgScore"),
  isgGapCount: document.querySelector("#isgGapCount"),
  eaImpact: document.querySelector("#eaImpact"),
  eaTemplateOutput: document.querySelector("#eaTemplateOutput"),
  eaChecklistOutput: document.querySelector("#eaChecklistOutput"),
  isgAssessmentOutput: document.querySelector("#isgAssessmentOutput"),
  isgGapsOutput: document.querySelector("#isgGapsOutput"),
  isgEvidenceOutput: document.querySelector("#isgEvidenceOutput"),
  eaMailOutput: document.querySelector("#eaMailOutput"),
  isgMailOutput: document.querySelector("#isgMailOutput"),
  generateLldBtn: document.querySelector("#generateLldBtn"),
  exportLldBtn: document.querySelector("#exportLldBtn"),
  reviewFlow: document.querySelector("#reviewFlow"),
  lldInput: document.querySelector("#lldInput"),
  claimInput: document.querySelector("#claimInput"),
  lldCoverageOutput: document.querySelector("#lldCoverageOutput"),
  lldGapOutput: document.querySelector("#lldGapOutput"),
  configReviewOutput: document.querySelector("#configReviewOutput"),
  claimReviewOutput: document.querySelector("#claimReviewOutput"),
  technicalExplanationOutput: document.querySelector("#technicalExplanationOutput"),
  functionalExplanationOutput: document.querySelector("#functionalExplanationOutput"),
  lldMailOutput: document.querySelector("#lldMailOutput"),
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
  {
    id: "mojibake-encoding",
    title: "Possible corrupted pasted characters or encoding issue",
    severity: "medium",
    pattern: /[\u00e2\ufffd]/,
    description: "Corrupted characters can break compilation or make logs/reports unreadable.",
    fix: "Remove corrupted characters or save/compile with the correct UTF-8 encoding.",
  },
  {
    id: "filewriter-dynamic-path",
    title: "Dynamic file write path needs validation",
    severity: "medium",
    pattern: /new\s+FileWriter\s*\(\s*[A-Za-z0-9_]+|Files\.write\s*\(\s*[A-Za-z0-9_]+/i,
    description: "File paths built from variables can overwrite unexpected files if inputs become external.",
    fix: "Validate and constrain output paths before writing files.",
  },
  {
    id: "mutable-map-return",
    title: "Mutable internal map may be exposed",
    severity: "medium",
    pattern: /Map<[^>]+>\s+get[A-Za-z0-9_]*\s*\(\)\s*\{\s*return\s+[A-Za-z0-9_]+;\s*\}/,
    description: "Returning an internal mutable collection allows external code to change object state unexpectedly.",
    fix: "Return an unmodifiable copy instead of exposing internal mutable state.",
  },
  {
    id: "interrupted-no-reinterrupt",
    title: "InterruptedException may not restore interrupt status",
    severity: "medium",
    pattern: /catch\s*\([^)]*InterruptedException[^)]*\)\s*\{(?![^}]*Thread\.currentThread\(\)\.interrupt\(\))/s,
    description: "Swallowing interruption can make shutdown and cancellation unreliable.",
    fix: "Call Thread.currentThread().interrupt() when InterruptedException is caught.",
  },
  {
    id: "quantity-no-validation",
    title: "Quantity input may lack positive-value validation",
    severity: "medium",
    pattern: /(addItem|reduceStock)\s*\([^)]*int\s+quantity[^)]*\)\s*\{(?![^}]*quantity\s*<=\s*0)(?![^}]*quantity\s*<\s*1)/s,
    description: "Negative or zero quantities can corrupt inventory/order calculations.",
    fix: "Validate quantity is positive before stock or order calculations.",
  },
  {
    id: "money-double",
    title: "Money represented with double",
    severity: "low",
    pattern: /\bdouble\s+(price|subtotal|finalTotal|amount|tax|discount)|double\s+calculate\s*\(/i,
    description: "Floating point arithmetic can introduce rounding errors in financial calculations.",
    fix: "Use BigDecimal or a money type for financial calculations.",
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
elements.generateWorkbenchBtn.addEventListener("click", renderWorkbench);
elements.exportWorkbenchBtn.addEventListener("click", exportWorkbench);
elements.generateSignoffBtn.addEventListener("click", renderSignoffCenter);
elements.exportSignoffBtn.addEventListener("click", exportSignoffPack);
elements.generateLldBtn.addEventListener("click", renderLldCenter);
elements.exportLldBtn.addEventListener("click", exportLldReview);

elements.filterButtons.forEach((button) => {
  button.addEventListener("click", () => {
    state.filter = button.dataset.filter;
    elements.filterButtons.forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    renderFindings();
  });
});

renderReviewPack();
renderWorkbench();
renderSignoffCenter();
renderLldCenter();

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

  const logFindings = analyzeLogs(elements.logInput.value);

  if (!sources.length && !logFindings.length && !elements.logInput.value.trim()) {
    state.findings = [];
    state.reviewPack = null;
    renderSummary();
    renderFindings();
    renderReviewPack();
    return;
  }

  state.findings = sources.flatMap((file) => scanSource(file));
  const apiInventory = extractApiInventory(sources);
  state.findings.push(...logFindings);
  const applicationFlow = explainApplicationFlow(sources, apiInventory);
  state.reviewPack = buildReviewPack(state.findings, sources, apiInventory, logFindings, applicationFlow);
  renderSummary(sources.length);
  renderFindings();
  renderReviewPack();
  renderWorkbench();
  renderSignoffCenter();
  renderLldCenter();
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

function extractApiInventory(sources) {
  const apiMap = new Map();

  sources.forEach((source) => {
    source.content.split(/\r?\n/).forEach((line, index) => {
      const matches = [
        ...line.matchAll(/\b(fetch|axios\.(get|post|put|patch|delete)|client\.(get|post|put|patch|delete))\s*\(\s*["'`]([^"'`]+)["'`]/gi),
        ...line.matchAll(/\b(GET|POST|PUT|PATCH|DELETE)\s+([/][A-Za-z0-9_./:{}?-]+)/gi),
        ...line.matchAll(/\b(url|endpoint|path)\s*[:=]\s*["'`]([^"'`]*\/[A-Za-z0-9_./:{}?-]+)["'`]/gi),
      ];

      matches.forEach((match) => {
        const rawMethod = (match[2] || match[1] || "UNKNOWN").toUpperCase();
        const method = ["GET", "POST", "PUT", "PATCH", "DELETE"].includes(rawMethod)
          ? rawMethod
          : inferMethod(line);
        const endpoint = normalizeEndpoint(lastMatchGroup(match));
        if (!endpoint || endpoint.length < 2) return;
        const key = `${method} ${endpoint}`;
        const existing = apiMap.get(key) || {
          method,
          endpoint,
          files: new Set(),
          firstLine: index + 1,
          risk: classifyApiRisk(endpoint, line),
          reviewed: "Needs review",
        };
        existing.files.add(source.name);
        existing.risk = mergeRisk(existing.risk, classifyApiRisk(endpoint, line));
        apiMap.set(key, existing);
      });
    });
  });

  return [...apiMap.values()].map((api) => ({
    method: api.method,
    endpoint: api.endpoint,
    files: [...api.files],
    firstLine: api.firstLine,
    risk: api.risk,
    reviewed: api.reviewed,
    reviewFocus: apiReviewFocus(api.endpoint),
  }));
}

function analyzeLogs(logText) {
  const patterns = [
    ["log-secret", "Secret or token may appear in logs", "critical", /(api[_-]?key|secret|token|password|authorization|bearer)\s*[:=]?\s*(bearer\s+)?[A-Za-z0-9_.:/+=-]{8,}/i, "Remove value from logs and rotate if real."],
    ["log-pii", "PII or banking identifier may appear in logs", "high", /(accountNumber|customerId|cif|pan|iban|aadhaar|ssn|cardNumber|mobileNumber|email)\s*[:=]/i, "Mask PII and banking identifiers."],
    ["log-stacktrace", "Stack trace or internal error exposed", "medium", /(Exception|StackTrace|NullPointerException|TypeError|ReferenceError|at\s+[A-Za-z0-9_.]+\()/, "Return generic errors and keep detailed traces server-side only."],
    ["log-auth-failure", "Authentication failure pattern", "medium", /(401|403|invalid otp|otp failed|login failed|unauthorized|forbidden)/i, "Check lockout, alerting, and user-safe messages."],
    ["log-timeout", "Timeout or integration instability", "medium", /(timeout|timed out|ECONNRESET|ENOTFOUND|503|504|gateway)/i, "Confirm retry, idempotency, and escalation ownership."],
  ];

  return String(logText || "")
    .split(/\r?\n/)
    .flatMap((line, index) =>
      patterns
        .filter(([, , , pattern]) => pattern.test(line))
        .map(([id, title, severity, , fix]) => ({
          id,
          title,
          severity,
          description: title,
          fix,
          file: "pasted-logs",
          line: index + 1,
          snippet: line.trim().slice(0, 360),
        })),
    );
}

function explainApplicationFlow(sources, apiInventory = []) {
  const classNames = new Set();
  const methodNames = new Set();
  const filesByType = {
    mobile: [],
    frontend: [],
    backend: [],
    config: [],
    logs: [],
    tests: [],
  };

  sources.forEach((source) => {
    const name = (source.name || "").toLowerCase();
    const content = source.content || "";
    for (const match of content.matchAll(/\b(class|interface|enum)\s+([A-Za-z0-9_]+)/g)) {
      classNames.add(match[2]);
    }
    for (const match of content.matchAll(/\b(public|private|protected|async|function)\s+[A-Za-z0-9_<>,\[\]\s]+\s+([A-Za-z0-9_]+)\s*\(/g)) {
      methodNames.add(match[2]);
    }

    if (/android|ios|mobile|react-native|swift|kotlin/.test(name)) filesByType.mobile.push(source.name);
    else if (/frontend|screen|component|page|tsx|jsx|html|css/.test(name)) filesByType.frontend.push(source.name);
    else if (/api|service|controller|repository|backend|java|kt|ts|js/.test(name)) filesByType.backend.push(source.name);
    else if (/\.(json|ya?ml|properties|gradle|xml|env)$/.test(name)) filesByType.config.push(source.name);
    else if (/\.log$/.test(name)) filesByType.logs.push(source.name);
    if (/(\.test\.|\.spec\.|__tests__|test\/|tests\/)/.test(name)) filesByType.tests.push(source.name);
  });

  const highRiskApis = apiInventory.filter((api) => api.risk !== "low");
  return {
    summary: [
      `Files reviewed: ${sources.length}`,
      `Classes/interfaces detected: ${classNames.size}`,
      `Methods/functions detected: ${methodNames.size}`,
      `APIs/endpoints detected: ${apiInventory.length}`,
      `High/medium risk APIs: ${highRiskApis.length}`,
    ],
    likelyFlow: [
      filesByType.mobile.length && "Mobile/UI layer collects user input and calls service/API layer.",
      filesByType.frontend.length && "Frontend components/screens appear to handle user interaction and API calls.",
      filesByType.backend.length && "Backend/service layer appears to process business logic, integration calls, and data operations.",
      apiInventory.length && "API layer should be reviewed for authentication, authorization, validation, timeout, retry, and error mapping.",
      filesByType.config.length && "Configuration files should be reviewed for environment values, secrets, endpoints, and security flags.",
      filesByType.logs.length && "Logs should be reviewed for errors, correlation IDs, PII masking, and integration ownership.",
      filesByType.tests.length ? "Automated tests are present and should be mapped to FS/security scenarios." : "No obvious test files detected; request unit/SIT/UAT evidence.",
    ].filter(Boolean),
    keyComponents: [...classNames].slice(0, 30),
    keyMethods: [...methodNames].slice(0, 30),
    filesByType,
    reviewQuestions: [
      "What is the entry point and trigger for this change?",
      "Which APIs/systems are upstream and downstream?",
      "Where is authentication and authorization enforced?",
      "Where is customer/financial data stored, logged, cached, or transmitted?",
      "What happens on timeout, retry, duplicate request, and partial failure?",
      "Which team owns each API, log, defect, and deployment step?",
    ],
  };
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
  renderWorkbench();
  renderSignoffCenter();
  renderLldCenter();
  elements.reportInput.value = "";
}

function buildReviewPack(findings, sources, apiInventory = extractApiInventory(sources), logFindings = analyzeLogs(elements.logInput.value), applicationFlow = explainApplicationFlow(sources, apiInventory)) {
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
  const highRiskApis = apiInventory.filter((api) => api.risk !== "low");

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
    apiReview: apiInventory,
    logAnalysis: {
      totalFindings: logFindings.length,
      findings: logFindings,
      requiredActions: [
        "Confirm logs do not contain tokens, passwords, OTPs, PANs, account numbers, or customer identifiers.",
        "Confirm correlation IDs exist for integration tracing without exposing sensitive data.",
        "Confirm timeout/retry errors identify owning team, API, timestamp, environment, and request ID.",
      ],
    },
    communication: buildCommunicationPack(findings, apiInventory, logFindings, decision, riskScore, highRiskApis),
    applicationFlow,
  };
}

function buildCommunicationPack(findings, apiInventory, logFindings, decision, riskScore, highRiskApis) {
  const blockers = findings.filter((finding) => ["critical", "high"].includes(finding.severity));
  const topIssues = blockers.slice(0, 6).map((finding) => `${finding.severity.toUpperCase()}: ${finding.file}:${finding.line} ${finding.title}`);
  const apiLines = highRiskApis.slice(0, 8).map((api) => `${api.method} ${api.endpoint} - ${api.risk} risk`);
  const logLines = logFindings.slice(0, 6).map((finding) => `${finding.severity.toUpperCase()}: ${finding.file}:${finding.line} ${finding.title}`);

  return {
    vendorMessage: [
      `Subject: ${decision === "Reject" || decision === "Hold" ? "Action Required" : "Review Update"}: Vendor code review findings and evidence request`,
      "",
      "Hi Team,",
      "",
      `We completed the local review pass. Current decision is ${decision} with risk score ${riskScore}.`,
      blockers.length
        ? "Please address the below blocking/security findings and share remediation evidence:"
        : "No critical/high automated findings are currently open, but closure evidence is still required:",
      ...bulletLines(topIssues.length ? topIssues : ["SAST, SCA, secret scan, unit test, and release build evidence required."]),
      "",
      "Please provide fix commits, test proof, owner, ETA, and retest notes for each item.",
      "",
      "Regards,",
    ].join("\n"),
    apiReviewMessage: [
      "Subject: API review status and integration evidence required",
      "",
      "Hi Team,",
      "",
      `We identified ${apiInventory.length} API/endpoints from the submitted source. ${highRiskApis.length} need focused integration/security review.`,
      ...bulletLines(apiLines.length ? apiLines : ["No high-risk API patterns detected by the local parser. Manual API contract review is still required."]),
      "",
      "Please share API contracts, auth scheme, request/response samples with masked data, timeout/retry behavior, error mapping, and owning team contacts.",
      "",
      "Regards,",
    ].join("\n"),
    logIssueMessage: [
      "Subject: Log analysis findings and integration follow-up",
      "",
      "Hi Team,",
      "",
      `Log analysis found ${logFindings.length} item(s) requiring review.`,
      ...bulletLines(logLines.length ? logLines : ["No log findings imported or detected. Please share sanitized logs with correlation IDs if analysis is needed."]),
      "",
      "Please confirm masking, correlation ID, timestamp, environment, API name, owning team, retry behavior, and closure action.",
      "",
      "Regards,",
    ].join("\n"),
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
  renderList(
    elements.apiInventoryList,
    pack.apiReview.length
      ? pack.apiReview.map((api) => `${api.method} ${api.endpoint} - ${api.risk} risk - ${api.reviewFocus}`)
      : ["No API endpoints detected. Import source or review API contracts manually."],
  );
  renderList(elements.applicationFlowList, [
    ...pack.applicationFlow.summary,
    ...pack.applicationFlow.likelyFlow,
    ...pack.applicationFlow.reviewQuestions.map((question) => `Review question: ${question}`),
  ]);
  renderList(
    elements.logAnalysisList,
    pack.logAnalysis.findings.length
      ? pack.logAnalysis.findings.map((finding) => `${finding.severity.toUpperCase()}: line ${finding.line} - ${finding.title}. ${finding.fix}`)
      : pack.logAnalysis.requiredActions,
  );
  elements.vendorMessage.textContent = pack.communication.vendorMessage;
  elements.apiMessage.textContent = pack.communication.apiReviewMessage;
  elements.logMessage.textContent = pack.communication.logIssueMessage;
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

function buildWorkbenchPack() {
  const pack = state.reviewPack || buildReviewPack(state.findings, currentSources());
  const appName = elements.wbAppName.value.trim() || "Application / Module";
  const devTitle = elements.wbDevTitle.value.trim() || "Development / CR Title";
  const environment = elements.wbEnvironment.value;
  const platform = elements.wbPlatform.value;
  const pocs = elements.wbPocs.value.trim() || "POC details pending";
  const fsSummary = elements.wbFsSummary.value.trim() || "FS summary pending";
  const issues = elements.wbIssues.value.trim() || "No open issues captured";
  const today = new Date().toISOString().slice(0, 10);
  const blockers = state.findings.filter((finding) => ["critical", "high"].includes(finding.severity));
  const decision = pack.decision || "Not reviewed";

  const trackerRow = [
    today,
    appName,
    devTitle,
    platform,
    environment,
    decision,
    pack.riskScore || 0,
    state.findings.length,
    (pack.apiReview || []).length,
    (pack.logAnalysis && pack.logAnalysis.totalFindings) || 0,
    blockers.length ? "Blocked / action required" : "On track / evidence pending",
    pocs.replace(/\r?\n/g, " | "),
  ].join("\t");

  const fsReview = [
    "Scope matches FS and no hidden out-of-scope behavior is present.",
    "API contracts, request/response fields, validation, errors, and retry behavior are documented.",
    "Frontend/mobile screens match FS, including empty/error/loading/session-expired states.",
    "Backend authorization is server-side and not only controlled by UI visibility.",
    "Audit, notification, reconciliation, and rollback behavior are defined where money movement exists.",
    "Non-functional requirements cover performance, availability, logging, monitoring, and support ownership.",
    "Security/privacy requirements cover masking, storage, telemetry, permissions, and data retention.",
  ];

  const crReadiness = [
    "CR description includes business reason, scope, impacted applications, and rollback plan.",
    "Implementation, unit test, SIT/UAT, security review, and deployment evidence are attached.",
    "All dependent teams and POCs are listed with approval status.",
    "Open defects, known issues, risk acceptance, and workaround notes are documented.",
    "Deployment steps, config changes, feature flags, and smoke test steps are documented.",
    "Backout plan, monitoring plan, and post-deployment validation owner are documented.",
  ];

  const signoff = [
    "EA signoff: architecture impact, integration pattern, data flow, and NFR impact reviewed.",
    "ISG signoff: SAST/SCA/secret scan, security exceptions, and remediation evidence reviewed.",
    "Business signoff: FS scope, UAT evidence, and open issue acceptance reviewed.",
    "Operations signoff: monitoring, alerts, support SOP, and escalation matrix reviewed.",
    "Release signoff: CR, deployment plan, rollback plan, and implementation window reviewed.",
  ];

  const statusMail = [
    `Subject: Status Update - ${devTitle} - ${appName} - ${environment}`,
    "",
    "Hi Team,",
    "",
    `Please find the current status for ${devTitle}.`,
    "",
    `Application/Module: ${appName}`,
    `Platform: ${platform}`,
    `Environment: ${environment}`,
    `Review Decision: ${decision}`,
    `Risk Score: ${pack.riskScore || 0}`,
    `Findings: ${state.findings.length}`,
    `APIs Reviewed/Identified: ${(pack.apiReview || []).length}`,
    `Log Findings: ${(pack.logAnalysis && pack.logAnalysis.totalFindings) || 0}`,
    "",
    "Current Issues/Risks:",
    issues,
    "",
    "Required Actions:",
    ...bulletLines((pack.releaseGates || []).slice(0, 6)),
    "",
    "POCs / Dependencies:",
    pocs,
    "",
    "Regards,",
  ].join("\n");

  const issueMail = [
    `Subject: Action Required - Issue Fixing Required - ${devTitle}`,
    "",
    "Hi Team,",
    "",
    "During review/testing, the below issue(s) require action before closure:",
    "",
    issues,
    "",
    blockers.length ? "Blocking Findings:" : "Review Notes:",
    ...bulletLines(
      blockers.length
        ? blockers.slice(0, 8).map((finding) => `${finding.severity.toUpperCase()} - ${finding.file}:${finding.line} - ${finding.title}`)
        : ["Please share fix commit, RCA, test proof, owner, and ETA if any issue is confirmed."],
    ),
    "",
    "Expected Response:",
    "- RCA",
    "- Fix commit/build version",
    "- Test evidence",
    "- Owner and ETA",
    "- Confirmation of impacted applications",
    "",
    "Regards,",
  ].join("\n");

  const gammaOutline = [
    `Title: ${devTitle} - Integration Review Summary`,
    "",
    "Slide 1: Executive Summary",
    `- Application: ${appName}`,
    `- Environment: ${environment}`,
    `- Decision: ${decision}`,
    `- Risk Score: ${pack.riskScore || 0}`,
    "",
    "Slide 2: Scope and FS Summary",
    `- ${fsSummary}`,
    "",
    "Slide 3: API Review",
    ...bulletLines((pack.apiReview || []).slice(0, 10).map((api) => `${api.method} ${api.endpoint} - ${api.risk} risk`)),
    "",
    "Slide 4: Security and Code Review Findings",
    ...bulletLines(state.findings.slice(0, 10).map((finding) => `${finding.severity.toUpperCase()} - ${finding.title}`)),
    "",
    "Slide 5: Log Analysis",
    ...bulletLines(
      pack.logAnalysis && pack.logAnalysis.findings.length
        ? pack.logAnalysis.findings.slice(0, 8).map((finding) => `${finding.severity.toUpperCase()} - ${finding.title}`)
        : ["No log findings captured. Sanitized logs required if issue analysis is needed."],
    ),
    "",
    "Slide 6: Open Issues and Risks",
    `- ${issues.replace(/\r?\n/g, "\n- ")}`,
    "",
    "Slide 7: Signoffs and Next Steps",
    ...bulletLines(signoff),
  ].join("\n");

  return {
    generatedAt: new Date().toISOString(),
    appName,
    devTitle,
    environment,
    platform,
    pocs,
    fsSummary,
    issues,
    trackerRow,
    fsReview,
    crReadiness,
    signoff,
    statusMail,
    issueMail,
    gammaOutline,
  };
}

function renderWorkbench() {
  const workbench = buildWorkbenchPack();
  elements.trackerOutput.textContent = workbench.trackerRow;
  renderList(elements.fsReviewOutput, workbench.fsReview);
  renderList(elements.crReadinessOutput, workbench.crReadiness);
  renderList(elements.signoffOutput, workbench.signoff);
  elements.statusMailOutput.textContent = workbench.statusMail;
  elements.issueMailOutput.textContent = workbench.issueMail;
  elements.gammaOutput.textContent = workbench.gammaOutline;
  elements.exportWorkbenchBtn.disabled = false;
}

function exportWorkbench() {
  const workbench = buildWorkbenchPack();
  const blob = new Blob([JSON.stringify(workbench, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `integration-work-pack-${new Date().toISOString().slice(0, 10)}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

function buildSignoffPack() {
  const reviewPack = state.reviewPack || buildReviewPack(state.findings, currentSources());
  const workbench = buildWorkbenchPack();
  const appName = workbench.appName;
  const devTitle = workbench.devTitle;
  const pattern = elements.eaPattern.value;
  const dataClassification = elements.dataClassification.value;
  const internetFacing = elements.internetFacing.value;
  const piiInvolved = elements.piiInvolved.value;
  const dataFlow = elements.eaDataFlow.value.trim() || "Data flow pending.";
  const dependencies = elements.eaDependencies.value.trim() || "Dependencies pending.";
  const evidenceText = elements.isgEvidence.value.trim();
  const exceptions = elements.securityExceptions.value.trim() || "No exceptions captured.";
  const evidenceLower = evidenceText.toLowerCase();
  const blockerCount = state.findings.filter((finding) => ["critical", "high"].includes(finding.severity)).length;

  const evidenceChecks = [
    ["SAST report", /sast|sonar|semgrep|checkmarx|fortify|codeql/.test(evidenceLower)],
    ["SCA/dependency report", /sca|dependency|cve|snyk|dependency-check/.test(evidenceLower)],
    ["Secret scan", /secret|gitleaks|credential/.test(evidenceLower)],
    ["API security evidence", /api|auth|authorization|rate|replay|idempotency/.test(evidenceLower)],
    ["TLS/certificate validation", /tls|ssl|certificate|pinning|mitm/.test(evidenceLower)],
    ["Secure storage evidence", /secure storage|keychain|keystore|encrypted storage/.test(evidenceLower)],
    ["Logging redaction evidence", /log|mask|redact|telemetry/.test(evidenceLower)],
    ["Unit/SIT/UAT evidence", /unit|sit|uat|test evidence|coverage/.test(evidenceLower)],
  ];

  const gaps = evidenceChecks.filter(([, passed]) => !passed).map(([name]) => `${name} not captured.`);
  if (blockerCount > 0) gaps.unshift(`${blockerCount} critical/high code or log finding(s) must be resolved or risk accepted.`);
  if (internetFacing === "Yes") gaps.push("Internet-facing impact requires explicit threat model, WAF/rate-limit, and VA/PT evidence.");
  if (piiInvolved === "Yes" && !/privacy|dpia|mask|retention|consent/i.test(evidenceText)) gaps.push("PII/financial data requires privacy, masking, retention, and logging evidence.");
  if (exceptions !== "No exceptions captured." && !/approver|expiry|owner|compensating/i.test(exceptions)) gaps.push("Security exceptions require owner, approver, expiry, and compensating control.");

  const score = Math.max(0, 100 - gaps.length * 10 - blockerCount * 15);
  const decision = blockerCount > 0 || score < 60 ? "Not ready" : gaps.length ? "Ready with gaps" : "Ready";
  const eaImpact = internetFacing === "Yes" || dataClassification === "Restricted" || piiInvolved === "Yes" ? "High" : "Medium";

  const eaChecklist = [
    "Architecture pattern and impacted systems are documented.",
    "Data flow, trust boundaries, source/target systems, and integration ownership are clear.",
    "API contracts, authentication, authorization, timeout, retry, and error handling are documented.",
    "NFRs cover performance, availability, scalability, monitoring, and support.",
    "Deployment, rollback, config, certificate/firewall, and operational dependencies are documented.",
    "Security/privacy controls are mapped to data classification and platform.",
  ];

  const evidenceRequired = [
    "SAST report with no unresolved critical/high findings.",
    "SCA/dependency report with CVE and license status.",
    "Secret scan report.",
    "API security test evidence for authZ, replay, rate limit, idempotency, and input validation.",
    "TLS/certificate validation or pinning evidence where applicable.",
    "Secure storage and logging redaction evidence.",
    "Unit/SIT/UAT evidence with build number and test date.",
    "Risk acceptance document for every exception.",
  ];

  const eaTemplate = [
    `EA Review Template - ${devTitle}`,
    "",
    `Application/Module: ${appName}`,
    `Architecture Pattern: ${pattern}`,
    `Platform: ${workbench.platform}`,
    `Environment: ${workbench.environment}`,
    `Data Classification: ${dataClassification}`,
    `Internet Facing: ${internetFacing}`,
    `PII/Financial Data: ${piiInvolved}`,
    "",
    "1. Business / Functional Scope",
    workbench.fsSummary,
    "",
    "2. Architecture Overview",
    `Pattern: ${pattern}`,
    `Impact: ${eaImpact}`,
    "",
    "3. Data Flow",
    dataFlow,
    "",
    "4. Dependencies",
    dependencies,
    "",
    "5. API / Integration Summary",
    ...(reviewPack.apiReview || []).slice(0, 20).map((api) => `- ${api.method} ${api.endpoint} (${api.risk}) - ${api.reviewFocus}`),
    "",
    "6. NFR / Operations",
    "- Availability, performance, timeout, retry, monitoring, alerts, and support ownership to be confirmed.",
    "",
    "7. Security / Privacy",
    `- ISG readiness: ${decision}`,
    `- Open gaps: ${gaps.length}`,
    `- Exceptions: ${exceptions}`,
    "",
    "8. Deployment / Rollback",
    "- Deployment steps, feature flags/config, smoke test, rollback, and post-deployment validation to be attached.",
  ].join("\n");

  const eaMail = [
    `Subject: EA Signoff Request - ${devTitle} - ${appName}`,
    "",
    "Hi EA Team,",
    "",
    "Please review the architecture/signoff details for the below change.",
    "",
    `Application/Module: ${appName}`,
    `Change: ${devTitle}`,
    `Pattern: ${pattern}`,
    `Environment: ${workbench.environment}`,
    `Architecture Impact: ${eaImpact}`,
    "",
    "Attached/Included:",
    "- EA review template",
    "- Data flow",
    "- API/dependency summary",
    "- NFR/operations notes",
    "- Security/ISG readiness summary",
    "",
    "Regards,",
  ].join("\n");

  const isgMail = [
    `Subject: ISG Pre-Assessment / Signoff Request - ${devTitle} - ${appName}`,
    "",
    "Hi ISG Team,",
    "",
    `We completed a pre-assessment before formal ISG submission. Current readiness: ${decision}, score: ${score}.`,
    "",
    "Open Gaps:",
    ...bulletLines(gaps.length ? gaps : ["No open pre-assessment gaps captured."]),
    "",
    "Evidence Available:",
    evidenceText || "Evidence details pending.",
    "",
    "Exceptions / Risk Acceptance:",
    exceptions,
    "",
    "Regards,",
  ].join("\n");

  return {
    generatedAt: new Date().toISOString(),
    decision,
    score,
    gaps,
    eaImpact,
    evidenceChecks: evidenceChecks.map(([name, passed]) => ({ name, status: passed ? "Available" : "Missing" })),
    evidenceRequired,
    eaChecklist,
    eaTemplate,
    eaMail,
    isgMail,
  };
}

function renderSignoffCenter() {
  const pack = buildSignoffPack();
  elements.isgDecision.textContent = pack.decision;
  elements.isgScore.textContent = pack.score;
  elements.isgGapCount.textContent = pack.gaps.length;
  elements.eaImpact.textContent = pack.eaImpact;
  elements.eaTemplateOutput.textContent = pack.eaTemplate;
  renderList(elements.eaChecklistOutput, pack.eaChecklist);
  renderList(elements.isgAssessmentOutput, pack.evidenceChecks.map((item) => `${item.name}: ${item.status}`));
  renderList(elements.isgGapsOutput, pack.gaps.length ? pack.gaps : ["No gaps captured in pre-assessment."]);
  renderList(elements.isgEvidenceOutput, pack.evidenceRequired);
  elements.eaMailOutput.textContent = pack.eaMail;
  elements.isgMailOutput.textContent = pack.isgMail;
  elements.exportSignoffBtn.disabled = false;
}

function exportSignoffPack() {
  const pack = buildSignoffPack();
  const blob = new Blob([JSON.stringify(pack, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `ea-isg-signoff-pack-${new Date().toISOString().slice(0, 10)}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

function buildLldReview() {
  const sources = currentSources();
  const sourceText = sources.map((source) => source.content).join("\n").toLowerCase();
  const fileNames = sources.map((source) => source.name.toLowerCase()).join("\n");
  const lld = elements.lldInput.value.toLowerCase();
  const claims = elements.claimInput.value.toLowerCase();
  const reviewFlow = elements.reviewFlow.value;
  const pack = state.reviewPack || buildReviewPack(state.findings, sources);
  const apis = pack.apiReview || [];

  const coverageChecks = [
    ["Component flow", /flow|sequence|component|module|service/.test(lld)],
    ["API contracts", /api|endpoint|request|response|contract/.test(lld)],
    ["Timeout/retry behavior", /timeout|retry|circuit|fallback|resilien/.test(lld)],
    ["Error handling", /error|exception|failure|fallback|status code/.test(lld)],
    ["Security controls", /auth|authorization|token|tls|encrypt|mask|secret|isg/.test(lld)],
    ["Data handling", /data|pii|customer|account|cache|storage|retention/.test(lld)],
    ["CI/CD and quality gates", /ci|cd|pipeline|pmd|sonar|quality|build|publish/.test(lld)],
    ["Deployment/rollback", /deploy|rollback|release|feature flag|config/.test(lld)],
    ...profileCoverageChecks(reviewFlow, lld),
  ];

  const gaps = coverageChecks
    .filter(([, passed]) => !passed)
    .map(([name]) => `${name} is missing or unclear in LLD/walkthrough notes.`);

  if (apis.length && !/api|endpoint|contract/.test(lld)) {
    gaps.push(`${apis.length} API(s) detected in code, but API contracts are not clearly covered in LLD.`);
  }
  if (/timeout|webclient|axios|fetch|okhttp|retrofit/.test(sourceText) && !/timeout|retry/.test(lld)) {
    gaps.push("Code/config suggests client calls, but LLD does not clearly explain timeout/retry behavior.");
  }
  if (state.findings.some((finding) => ["critical", "high"].includes(finding.severity))) {
    gaps.push("Critical/high findings exist; LLD should mention remediation or risk acceptance before signoff.");
  }

  const configReview = [
    /pmd|checkstyle|sonar|lint/.test(sourceText + lld) ? "Quality/static-analysis configuration is referenced; confirm it runs in CI and blocks failures." : "Quality/static-analysis configuration not found; request PMD/Checkstyle/Sonar/lint evidence.",
    /pipeline|azure-pipelines|jenkins|github workflow|build|publish|ci|cd/.test(sourceText + lld + fileNames) ? "CI/CD is referenced; confirm branch, build, publish, approval, and artifact traceability." : "CI/CD evidence not found; request build/publish pipeline details.",
    /timeout|webclient|okhttp|retrofit|axios|fetch/.test(sourceText + lld) ? "Timeout/client configuration is referenced; confirm values, retry policy, and production config source." : "Timeout/client configuration not found; request service client timeout evidence.",
    /application\.ya?ml|application\.properties|config|env/.test(sourceText + lld + fileNames) ? "Application config is referenced; review endpoints, secrets, feature flags, and environment separation." : "Application config not evident; request environment config details.",
    ...profileConfigReview(reviewFlow, sourceText, lld, fileNames),
  ];

  const claimReview = [
    /working for me|my machine|local machine|sapient machine/.test(claims) && "Claim depends on local machine validation; request CI/SIT/UAT evidence from approved environment.",
    /devops|ci|cd|pipeline|build|publish/.test(claims) && "CI/CD ownership claimed; request pipeline run link/report, branch, artifact, and quality gate status.",
    /timeout|webclient|config/.test(claims) && "Timeout/config claimed; request actual config file path, values, environment override, and test evidence.",
    /pmd|checkstyle|standard/.test(claims) && "Code standardization claimed; request PMD/Checkstyle/Sonar report and failure threshold.",
    /credential|clone|access|repo/.test(claims) && "Repo/access process mentioned; request DevOps/ISG confirmation of approved access and audit trail.",
    ...profileClaimReview(reviewFlow, claims),
  ].filter(Boolean);

  const technicalExplanation = buildTechnicalExplanation(reviewFlow, pack, sourceText, lld);
  const functionalExplanation = buildFunctionalExplanation(reviewFlow, pack, lld);

  const mail = [
    "Subject: LLD / Code Walkthrough Clarifications Required",
    "",
    "Hi Team,",
    "",
    "Based on the LLD/code walkthrough review, please provide clarification/evidence for the below items before closure/signoff.",
    "",
    "LLD / Code Gaps:",
    ...bulletLines(gaps.length ? gaps : ["No major LLD coverage gaps captured by the local checklist."]),
    "",
    "Configuration / CI-CD Review:",
    ...bulletLines(configReview),
    "",
    "Claim vs Evidence:",
    ...bulletLines(claimReview.length ? claimReview : ["No specific developer claims captured. Please share evidence for all walkthrough statements."]),
    "",
    "Technical Explanation Required:",
    ...bulletLines(technicalExplanation),
    "",
    "Functional Explanation Required:",
    ...bulletLines(functionalExplanation),
    "",
    "Regards,",
  ].join("\n");

  return {
    generatedAt: new Date().toISOString(),
    coverageChecks: coverageChecks.map(([name, passed]) => ({ name, status: passed ? "Covered" : "Missing" })),
    gaps,
    configReview,
    claimReview,
    technicalExplanation,
    functionalExplanation,
    mail,
  };
}

function renderLldCenter() {
  const review = buildLldReview();
  renderList(elements.lldCoverageOutput, review.coverageChecks.map((item) => `${item.name}: ${item.status}`));
  renderList(elements.lldGapOutput, review.gaps.length ? review.gaps : ["No major LLD gaps captured."]);
  renderList(elements.configReviewOutput, review.configReview);
  renderList(elements.claimReviewOutput, review.claimReview.length ? review.claimReview : ["No specific claims entered."]);
  renderList(elements.technicalExplanationOutput, review.technicalExplanation);
  renderList(elements.functionalExplanationOutput, review.functionalExplanation);
  elements.lldMailOutput.textContent = review.mail;
  elements.exportLldBtn.disabled = false;
}

function exportLldReview() {
  const review = buildLldReview();
  const blob = new Blob([JSON.stringify(review, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `lld-evidence-review-${new Date().toISOString().slice(0, 10)}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

function profileCoverageChecks(reviewFlow, lld) {
  if (reviewFlow === "Mobile") {
    return [
      ["Mobile auth/session flow", /auth|login|session|token|otp|mfa|biometric/.test(lld)],
      ["Mobile API connection config", /api connection|base url|endpoint|client|webclient|retrofit|axios|fetch/.test(lld)],
      ["Mobile timeout configuration", /timeout|connect timeout|read timeout|webclient/.test(lld)],
      ["Mobile secure storage", /keychain|keystore|secure storage|encrypted storage|asyncstorage/.test(lld)],
      ["Mobile release and CI/CD evidence", /build|publish|pipeline|ci|cd|devops/.test(lld)],
      ["Mobile code quality gate", /pmd|checkstyle|sonar|lint|quality/.test(lld)],
    ];
  }
  if (reviewFlow === "Backend") {
    return [
      ["Backend controller/service/repository flow", /controller|service|repository|dao|database/.test(lld)],
      ["Backend transaction and rollback behavior", /transaction|rollback|commit|idempotency/.test(lld)],
      ["Backend observability", /log|monitor|alert|metric|trace|correlation/.test(lld)],
    ];
  }
  if (reviewFlow === "Frontend") {
    return [
      ["Frontend screen/state flow", /screen|component|state|route|validation/.test(lld)],
      ["Frontend API and error display behavior", /api|error|toast|message|fallback/.test(lld)],
      ["Frontend access control expectation", /role|permission|auth|protected/.test(lld)],
    ];
  }
  if (reviewFlow === "Integration") {
    return [
      ["Integration ownership and POC mapping", /owner|poc|team|dependency|system/.test(lld)],
      ["Integration timeout/retry/idempotency", /timeout|retry|idempotency|duplicate/.test(lld)],
      ["Integration reconciliation and support", /reconcile|support|monitor|alert|incident/.test(lld)],
    ];
  }
  if (reviewFlow === "Full stack") {
    return [
      ["End-to-end UI to API to data flow", /ui|frontend|api|backend|database|mobile/.test(lld)],
      ["Cross-application dependency mapping", /dependency|upstream|downstream|system|team/.test(lld)],
      ["End-to-end test evidence", /e2e|sit|uat|integration test|smoke/.test(lld)],
    ];
  }
  return [];
}

function profileConfigReview(reviewFlow, sourceText, lld, fileNames) {
  const combined = `${sourceText}\n${lld}\n${fileNames}`;
  if (reviewFlow !== "Mobile") return [];
  return [
    /auth|login|token|session/.test(combined)
      ? "Mobile auth management is referenced; confirm token lifecycle, logout, refresh, secure storage, and session timeout evidence."
      : "Mobile auth management not evident; request auth/session flow explanation.",
    /pmd|checkstyle|sonar|lint/.test(combined)
      ? "PMD/code-style/static checks are referenced; confirm report, gate threshold, and CI enforcement."
      : "PMD/code-style evidence not found; request quality gate proof.",
    /build|publish|pipeline|azure|jenkins|devops/.test(combined)
      ? "Build/publish pipeline is referenced; confirm approved branch, artifact, environment, and release traceability."
      : "Build/publish CI-CD evidence not found; request DevOps pipeline proof.",
    /timeout|webclient|retrofit|okhttp|axios|fetch/.test(combined)
      ? "Web client/API timeout is referenced; confirm actual timeout values and environment override."
      : "Web client timeout config not evident; request timeout config and test evidence.",
  ];
}

function profileClaimReview(reviewFlow, claims) {
  if (reviewFlow !== "Mobile") return [];
  return [
    /working for me|my machine|sapient machine|local/.test(claims) &&
      "Mobile validation cannot rely on individual/vendor machine; request approved device/environment, CI build, SIT/UAT evidence.",
    /master credential|credential|clone|repo|access/.test(claims) &&
      "Mobile repo access/cloning process must be approved; request DevOps/ISG confirmation and audit trail.",
    /devops|build|publish|pipeline/.test(claims) &&
      "Build/publish responsibility mentioned; request exact pipeline run and artifact evidence.",
    /config|api connection|timeout|webclient/.test(claims) &&
      "Config behavior mentioned; request config file path, values, masking, and environment-specific override proof.",
  ].filter(Boolean);
}

function buildTechnicalExplanation(reviewFlow, pack, sourceText, lld) {
  const common = [
    "Explain entry point, components/classes/modules, and how request moves through the code.",
    "Explain API calls, request/response mapping, timeout, retry, error handling, and fallback.",
    "Explain configuration source, environment override, feature flags, and secret handling.",
    "Explain evidence: CI/CD run, quality gate, unit/SIT/UAT result, and security scan status.",
  ];
  if (reviewFlow === "Mobile") {
    return [
      "Mobile technical flow: screen/action -> view model/state -> service/client -> API -> response -> UI state.",
      "Auth management: token/session storage, refresh, logout, device binding, OTP/MFA/biometric behavior.",
      "API connection config: base URL, headers, certificates/pinning, timeout values, retry/cancel behavior.",
      "Build/publish: branch, pipeline, artifact, environment, signing, debug disabled, test code excluded.",
      "Quality: PMD/Checkstyle/Sonar/lint report, rule set, gate threshold, and blocking behavior.",
      ...common,
    ];
  }
  if (reviewFlow === "Backend") {
    return [
      "Backend technical flow: controller -> service -> integration/repository -> response/error mapping.",
      "Transaction behavior: commit, rollback, idempotency, duplicate handling, timeout-after-processing.",
      ...common,
    ];
  }
  if (reviewFlow === "Frontend") {
    return [
      "Frontend technical flow: route/screen -> component state -> API client -> error/loading/success UI.",
      "Access control expectation: protected routes, role checks, server-side authorization dependency.",
      ...common,
    ];
  }
  return common;
}

function buildFunctionalExplanation(reviewFlow, pack, lld) {
  const common = [
    "Explain business trigger and user/system actor.",
    "Explain happy path, negative path, timeout path, and rollback/retry behavior.",
    "Explain impacted applications, teams, POCs, and pending dependencies.",
    "Explain acceptance criteria, test evidence, open risks, and signoff needed.",
  ];
  if (reviewFlow === "Mobile") {
    return [
      "Mobile functional flow: user opens screen, enters data, validates input, submits, sees success/failure state.",
      "Explain user-facing messages for invalid input, session expiry, API failure, timeout, and pending status.",
      "Explain sensitive data shown on screen, masked fields, screenshots, clipboard, notifications, and logs.",
      "Explain device/app states: background, resume, network loss, retry, app kill, upgrade, and logout.",
      ...common,
    ];
  }
  if (reviewFlow === "Integration") {
    return [
      "Integration functional flow: source system trigger, target system action, acknowledgement, failure handling.",
      "Explain reconciliation, duplicate handling, SLA, support team, and escalation path.",
      ...common,
    ];
  }
  return common;
}

function currentSources() {
  const pasted = elements.codeInput.value.trim();
  return state.files.length ? state.files : pasted ? [{ name: "pasted-code", content: pasted }] : [];
}

function buildMarkdownReport(pack, findings) {
  const sections = [
    ["Reviewed APIs", pack.apiReview.map((api) => `${api.method} ${api.endpoint} - ${api.risk} risk - ${api.reviewFocus}`)],
    ["Application Flow", [...pack.applicationFlow.summary, ...pack.applicationFlow.likelyFlow, ...pack.applicationFlow.reviewQuestions]],
    ["Log Analyzer", pack.logAnalysis.findings.length ? pack.logAnalysis.findings.map((finding) => `${finding.severity.toUpperCase()}: line ${finding.line} - ${finding.title}`) : pack.logAnalysis.requiredActions],
    ["Vendor Message", [pack.communication.vendorMessage]],
    ["API Team Message", [pack.communication.apiReviewMessage]],
    ["Log Issue Message", [pack.communication.logIssueMessage]],
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
  elements.logInput.value = "";
  elements.downloadBtn.disabled = true;
  elements.downloadPackBtn.disabled = true;
  renderSummary(0);
  elements.findingsList.innerHTML = `<div class="empty-state">Upload a folder, upload files, or paste code to run a private review.</div>`;
  renderReviewPack();
  renderWorkbench();
  renderSignoffCenter();
  renderLldCenter();
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

function inferMethod(line) {
  const lowered = line.toLowerCase();
  if (lowered.includes(".post") || lowered.includes("post")) return "POST";
  if (lowered.includes(".put") || lowered.includes("put")) return "PUT";
  if (lowered.includes(".patch") || lowered.includes("patch")) return "PATCH";
  if (lowered.includes(".delete") || lowered.includes("delete")) return "DELETE";
  return "GET";
}

function normalizeEndpoint(endpoint) {
  return String(endpoint)
    .replace(/^https?:\/\/[^/]+/i, "")
    .replace(/\?.*$/, "")
    .trim();
}

function lastMatchGroup(match) {
  for (let index = match.length - 1; index >= 1; index -= 1) {
    if (match[index]) return match[index];
  }
  return "";
}

function classifyApiRisk(endpoint, line) {
  const value = `${endpoint} ${line}`.toLowerCase();
  if (/(transfer|payment|beneficiary|otp|mfa|login|password|pin|card|account|statement)/.test(value)) return "high";
  if (/(profile|customer|user|session|token|auth|limit|balance)/.test(value)) return "medium";
  return "low";
}

function mergeRisk(a, b) {
  const order = { low: 1, medium: 2, high: 3 };
  return order[b] > order[a] ? b : a;
}

function apiReviewFocus(endpoint) {
  const value = endpoint.toLowerCase();
  if (/(transfer|payment)/.test(value)) return "Authorization, idempotency, limit checks, confirmation, audit trail, and timeout-after-debit handling.";
  if (/beneficiary/.test(value)) return "Cooling period, maker-checker where applicable, validation, fraud controls, and notification.";
  if (/(otp|mfa|login|password|pin)/.test(value)) return "Brute-force control, replay prevention, session binding, error leakage, and lockout.";
  if (/(account|statement|balance|profile|customer)/.test(value)) return "Customer authorization, PII masking, caching, and privacy logging.";
  return "Contract validation, auth, error handling, timeout, retry, and owning team.";
}

function bulletLines(items) {
  return items.map((item) => `- ${item}`);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
