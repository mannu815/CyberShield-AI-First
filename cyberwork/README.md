# CyberShield AI — Professional Multi-Page Defensive Security MVP

A local-first FastAPI web application with separate pages for the overview, passive website scanner, phishing/URL analysis, public DNS lookup, built-in defensive assistant, and scan history/reports.

## Run on Windows 11

**Important:** `requirements.txt` is in the project root (the same folder as `README.md` and `run_windows.bat`). Open PowerShell in that folder before running the commands below.

1. Confirm Python is installed: `py --version`.
2. Create a virtual environment:
   ```powershell
   py -m venv .venv
   ```
3. Install dependencies (use this exact command):
   ```powershell
   .\.venv\Scripts\python.exe -m pip install --upgrade pip
   .\.venv\Scripts\python.exe -m pip install -r .\requirements.txt
   ```
4. Start the app:
   ```powershell
   .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```
5. Open `http://127.0.0.1:8000` in your browser.

If PowerShell says it cannot find `requirements.txt`, you are not in the project root. Run `dir` and make sure `requirements.txt`, `README.md`, `run_windows.bat`, and the `app` folder are listed together.

## AI assistant setup (optional)

The assistant works in built-in fallback mode without an API key. For online Gemini answers, create a key at https://aistudio.google.com/app/apikey and set it in the same PowerShell window before starting the server:

```powershell
$env:GEMINI_API_KEY="YOUR_API_KEY"
$env:CYBERSHIELD_AI_PROVIDER="hybrid"
```

Keep the key private and never commit it to GitHub. Optional local AI requires Ollama installed and a model downloaded, for example `ollama pull llama3.2`. A cloud deployment cannot access Ollama running only on your laptop; configure the cloud provider separately.

## Separate pages
- `/` — dashboard
- `/scanner` — passive website configuration scanner
- `/phishing` — suspicious URL and message analysis hub
- `/url-checker` — URL heuristic analysis
- `/message-checker` — suspicious message analysis
- `/osint` — public DNS lookup
- `/assistant` — built-in defensive guidance
- `/history` — saved scans and JSON exports
- `/health` — health check

## Scope and safety
The website scanner performs limited passive configuration checks and is not a full vulnerability scanner. URL and message detection uses heuristics and can be wrong. DNS lookup only resolves public domain records available through the system resolver. The assistant is built-in rule-based guidance, not a connected generative AI service. Use scanning only on assets you own or are explicitly authorized to assess.

Keep local development bound to `127.0.0.1`. `run_windows.bat` explicitly enables local-development bypass for convenience; NEVER use that mode on a public server.

## Security upgrade notes
- HTTP Basic authentication uses PBKDF2-SHA256 password hashes. Create hashes with `python make_password_hash.py` and configure `CYBERSHIELD_ADMIN_PASSWORD_HASH` and `CYBERSHIELD_ANALYST_PASSWORD_HASH` in the hosting provider's secret/environment settings. Keep the service behind HTTPS.
- Admins can view `/api/admin/audit-logs`; both configured admin and analyst roles can run low-impact scans. In-memory rate limiting is per process and is not distributed across multiple instances.
- `CYBERSHIELD_AUTHORIZED_HOSTS` is a comma-separated hostname allowlist for the optional authorized mode. That mode performs only scoped passive checks (including robots.txt and sitemap.xml availability); it is not exploitation or penetration testing. The user must also enter `I_HAVE_WRITTEN_AUTHORIZATION`.
- TLS certificate expiry metadata is included when the target uses HTTPS. Reports can be exported as JSON or PDF.
- SSRF controls reject non-public IPs and internal hostnames and validate each redirect destination. This is defense-in-depth, not a guarantee against DNS rebinding or platform/network routing edge cases. Before public exposure, use provider-level egress controls/firewall rules that block private, loopback, link-local, and metadata ranges; ideally pin validated DNS addresses at connection time and test from the deployed environment.
- Set a persistent `CYBERSHIELD_DB` path on a persistent disk if using SQLite. Back up the database and test restore procedures. Multiple replicas should use a managed database and distributed rate limiting.
- `/health` is intentionally unauthenticated for deployment health checks and returns no secrets. Do not disable Windows Defender globally.



## Device Protection (Windows beta)

The `/device-protection` page performs read-only checks of Microsoft Defender status and recent Defender Operational events through local PowerShell. It may show Defender detections or disabled protection and can send browser notifications while the dashboard is open and notifications are allowed. It is not a full endpoint detection/response agent and cannot guarantee detection of every malware infection or unauthorized access. Keep Windows Security notifications and protections enabled. Alerts while the app is closed depend on Windows Security/Defender notifications; this app itself is not a background service. No remote access monitoring or keystroke/file surveillance is performed.


## Render deployment checklist (do not skip)
1. Set **Root Directory** to `CyberShield_AI_Upgraded` only if the repository has the project inside that subfolder; otherwise leave it blank.
2. Build command: `pip install -r requirements.txt`
3. Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. Add environment variables for both password hashes, usernames, `CYBERSHIELD_AUTHORIZED_HOSTS`, and `CYBERSHIELD_RATE_LIMIT`. Do not set `CYBERSHIELD_LOCAL_DEV=1`.
5. If using SQLite on Render, attach a persistent disk and set `CYBERSHIELD_DB=/var/data/cybershield.db` with the disk mounted at `/var/data`. Confirm backups and restore before relying on stored reports.
6. Add outbound network restrictions where the host supports them. App-level URL validation alone is not a complete SSRF boundary.
7. After deployment, test `/health`, authentication prompts, scan creation on a target you own, JSON/PDF exports, and persistence after a redeploy.

This release is a security-hardened MVP, not a fully production-certified multi-tenant platform: admin and analyst accounts are configured through environment variables, and scan history is shared in the database. Before onboarding unrelated customers, add per-user scan ownership, account lifecycle/password reset, CSRF/session strategy if moving away from Basic auth, centralized rate limiting, monitoring, and a managed database.


## Vulnerability coverage catalogue (v1.2)
The scanner now attaches a 100-item vulnerability coverage inventory to each scan and exposes it at `/api/vulnerability-coverage` (use `?mode=authorized` for the scoped mode). The inventory explicitly labels each item `assessed`, `partially_assessed`, or `not_assessed`. It does **not** claim that every vulnerability has been tested. Current remote checks cover selected response-level signals such as HTTPS/TLS certificate metadata, HSTS, CSP, cookie attributes, and clickjacking headers. Authorized mode has limited, read-only checks for robots.txt/sitemap.xml only.

Injection payloads, brute-force/credential-stuffing/password-spraying, session hijacking, XSS payloads, IDOR/BOLA/BFLA, file inclusion, XXE, request smuggling, RCE, race-condition, and denial-of-service testing are deliberately not performed against live targets. Those require a controlled lab, application-specific test accounts/source review, or dedicated tools configured with explicit scope. `not_assessed` means no conclusion was reached; it does not mean the target is secure.

## v1.3 — Local network utilities

The Network Tools page adds three low-impact defensive utilities:

- **Private/local ping** — one ping to a literal private, loopback, or link-local IP.
- **Limited open-port exposure check** — checks a fixed list of 15 common ports on one private/local IP; it does not sweep subnets or public hosts.
- **Nearby Wi-Fi inventory** — Windows 10/11 `netsh wlan show networks mode=bssid` read-only output; it never extracts saved Wi-Fi passwords.

Open `/network-tools` in the dashboard. JSON API routes are `POST /api/tools/ping`, `POST /api/tools/ports`, and `GET /api/tools/wifi`. `GET /api/tools/safety-notes` lists included and excluded features. These endpoints deliberately reject public IP targets for port checks.

This project does **not** create fake/evil-twin Wi-Fi, generate DoS/DDoS traffic, brute-force logins, crawl personal phone numbers, or perform covert camera hunting. The port exposure check can flag a reachable RTSP/video port but cannot prove a camera exists. It is a small defensive utility, not a complete network scanner or router vulnerability audit. Keep the app bound to localhost unless you have configured authentication and deployment security.


## v1.4 — Hybrid personal AI assistant

The `/assistant` page now supports an optional hybrid generative AI setup: it tries Gemini cloud AI when `GEMINI_API_KEY` is set, then local Ollama, and finally a built-in fallback. Configure `CYBERSHIELD_AI_PROVIDER=hybrid` (or `auto`, `gemini`, `ollama`) and see `.env.example`. Environment variables must be set in the shell or hosting provider; `.env.example` is a template, not an active secrets file. Never commit a real API key to GitHub. Gemini usage depends on current account quotas and billing rules.

Install Ollama from https://ollama.com, then run `ollama pull llama3.2` to enable local AI. For Gemini, create a key at https://aistudio.google.com/app/apikey and set `GEMINI_API_KEY` in your environment. On Render, use its Environment settings for secrets; a local Ollama service on your laptop will not be available to a hosted Render instance.

The assistant can execute only explicit, allowlisted local commands: `ping <private-IP>`, `ports <private-IP>`, and `wifi scan` (Windows only). It does not execute arbitrary model-generated code, shell commands, or URLs. The model's instructions are guidance, not a guarantee; application-level permissions and safety controls remain authoritative. The `/api/assistant/status` endpoint reports provider availability without exposing keys.

### Windows 11 assistant quick setup

**Local AI (no AI API subscription):** install Ollama from https://ollama.com, open PowerShell, run `ollama pull llama3.2`, then start CyberShield AI. Leave `CYBERSHIELD_AI_PROVIDER=hybrid` or set `$env:CYBERSHIELD_AI_PROVIDER="ollama"` in the same PowerShell window before launching Uvicorn.

**Cloud AI:** create a Gemini API key at https://aistudio.google.com/app/apikey, then in the same PowerShell window run `$env:GEMINI_API_KEY="YOUR_KEY_HERE"` and `$env:CYBERSHIELD_AI_PROVIDER="hybrid"` before launching Uvicorn. Do not paste the key into chat or commit it to source control. API availability, free quotas, and charges depend on the provider's current terms.

**Hybrid:** when a Gemini key is configured, Gemini is tried first; if it fails, the app tries Ollama. If neither is available, the built-in fallback still works. On Render, configure the Gemini key in the service's Environment settings; Ollama installed only on your laptop cannot serve a cloud-hosted app.

## v1.5 — Expanded security assessment and vulnerability intelligence

This upgrade expands the vulnerability taxonomy from 100 to 151 entries, adds additional response-header checks (Referrer-Policy, Permissions-Policy, CORS policy indicators, server-version disclosure, cache privacy headers, and COOP/CORP/COEP), and adds a small fixed-path, metadata-only exposure review in the explicitly allowlisted authorized mode. The response body for those paths is not stored. The dashboard includes a searchable vulnerability catalog and an NVD CVE lookup panel.

New endpoints:
- `GET /api/vulnerability-catalog` — complete catalog with assessment type labels.
- `GET /api/cve/CVE-YYYY-NNNN` — retrieves a public CVE record from the NIST NVD API; it does not test the scanned target.
- `GET /api/vulnerability-coverage` — per-scan coverage definitions.

The current remote scanner performs a limited set of low-impact checks; the remaining catalog entries are explicitly not assessed and may require source/configuration review, authenticated test accounts, or a controlled lab. It does not execute credential attacks, exploit payloads, code execution, destructive actions, or DoS/DDoS. Do not expose this application publicly without proper deployment hardening, credentials, network egress controls, and a persistent database configuration.

## Application-level test coverage (v1.8)
The scan report now includes a 15-module coverage matrix alongside findings. It distinguishes limited runtime observations (TLS/security headers/cookie attributes and, in authorized mode, a fixed small metadata-path review) from modules that require authenticated staging workflows or source/configuration review. The matrix is included in saved JSON scan results and shown in the dashboard.

Modules include XSS, SQL/NoSQL/LDAP/XPath/XML/OS/template injection, authentication/MFA/password reset, brute-force/credential-stuffing defenses, sessions/cookies, IDOR/BOLA and tenant isolation, SSRF defenses, CSRF, file uploads/path traversal, API/GraphQL, business logic/race conditions, DoS resilience/rate limits, dependencies/secrets, and transport/security headers.

**Status is intentionally conservative:** “manual/staging required” means that module was not remotely tested. It must never be interpreted as safe. The scanner does not send exploit payloads, attempt credentials, upload files, mutate records, access cloud metadata/private networks, or generate DoS/DDoS traffic. Use a deliberately vulnerable local training app or a separately approved staging environment for those tests. Real load testing must have an explicit written plan, rate/concurrency ceilings, monitoring, a stop condition, and owner approval.
