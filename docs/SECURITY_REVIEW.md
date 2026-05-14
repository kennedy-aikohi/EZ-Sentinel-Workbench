# Security Review

This review documents the secure design controls used in EZ Sentinel Workbench v6.0.

## OWASP-aligned controls

The current OWASP Top Ten project page identifies OWASP Top 10:2025 as the most current released version. The 2025 list includes categories such as Broken Access Control, Security Misconfiguration, Software Supply Chain Failures, Injection, Insecure Design, Security Logging & Alerting Failures, and Mishandling of Exceptional Conditions.

## Controls implemented

### Injection prevention

- Uses `subprocess.Popen([...], shell=False)`.
- Commands are built as argument arrays, not interpolated shell strings.
- Extra Args block `.exe` paths, pipes, redirection, `&`, `;`, and other shell control tokens.
- Tool profiles are locked to specific executables.

### Secure configuration

- User must explicitly select EZ Tools root, evidence root, and output root.
- The preview shows the exact executable path under **Tool locked to**.
- Unsupported known switches were removed from profiles.
- RECmd uses a dedicated argument builder to avoid missing required values such as `--sk` without a keyword.

### Software supply-chain minimization

- The GUI uses Python standard-library components only.
- The executable build uses PyInstaller only during packaging.
- External forensic parsers are not bundled; the user points the GUI to their known EZ Tools folder.

### Resource-exhaustion controls

- Evidence indexing runs in a background thread.
- Command preview uses cached artifact paths and does not recursively scan the disk.
- Long parser output streams to the GUI instead of waiting for a huge buffer at the end.
- bstrings stdout is redirected directly to a text file.
- GUI log retention is bounded.
- Parser runs have timeout control and a Stop button.
- Evidence indexing has a safety file limit.

### Logging and auditability

- Each parser run writes a run log under `_EZSentinelLogs`.
- The log includes the title, exact command preview, return code, status, reason, and output tails.

### Exception handling

- Worker-thread failures are posted back to the GUI as failed run status.
- Validation blocks execution for missing artifacts, missing tools, missing maps, or incomplete RECmd arguments.
