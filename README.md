# UniQueS — The Universal Quantum Scanner

[![CI](https://github.com/uni-que-s/uniques/actions/workflows/ci.yml/badge.svg)](https://github.com/uni-que-s/uniques/actions/workflows/ci.yml)
[![Live site](https://img.shields.io/badge/live%20site-uni-que-s.github.io%2Funiques-2563eb)](https://uni-que-s.github.io/uniques/)

### 🔗 [**See it live → uni-que-s.github.io/uniques**](https://uni-que-s.github.io/uniques/)

Overview, product showcase, and a [**zero-install live demo**](https://uni-que-s.github.io/uniques/demo/) — the real dashboard running fully in your browser, no install or backend required.

> **Find the quantum-vulnerable cryptography in your codebase and produce the CBOM regulators now require — running entirely on-prem, so your source never leaves your network.**

**A cryptography discovery & inventory scanner — not a vault.** UniQueS finds the
quantum-vulnerable cryptographic assets (RSA, ECC, DSA, Diffie-Hellman, legacy
symmetric/hashes, key material) hiding across your codebase, scores them for
post-quantum migration priority, tracks remediation to completion, and generates
the standards **CBOM** plus control-gap / audit-evidence reports mapped to FISMA,
CISA, FedRAMP, SOC 2, PCI-DSS, CNSA 2.0, and NIST CSF 2.0.

It doesn't *make* you quantum-safe — it tells you, honestly, where you aren't yet.
It closes the loop — **discover → prioritize → track → prove** — for the
"harvest-now, decrypt-later" threat that puts today's RSA/ECC traffic at risk once
a cryptographically-relevant quantum computer exists. Everything runs on-prem; your
source never leaves your network.

## Features

- **Cryptographic asset discovery** — a 59-pattern, language-agnostic scanner
  detects RSA, ECC (incl. Ed25519/X25519), DSA, Diffie-Hellman, legacy symmetric
  (DES/3DES/AES-128), broken hashes (MD5/SHA-1), RSA/EC/DSA private-key PEMs (incl.
  PGP key blocks), JWT/JOSE signing algorithms (RS/ES/PS), Web Crypto RSA, SSH key
  types in IaC, language-specific key APIs (Java, Ruby, PHP, Rust, Go, Python),
  and RSA X.509 certs across 25+ file types. Scans a **local path** or
  shallow-clones a **public or private Git repo** (GitHub/GitLab/Bitbucket;
  private via an access token sent as an auth header, kept out of the URL and
  never logged).
- **Certificate & TLS configuration discovery** — a built-in, zero-dependency
  DER/ASN.1 parser reads every X.509 certificate it finds (PEM blocks and chains,
  binary DER under any cert/key extension — including mislabeled `.pem`/`.key`
  exports — headerless base64 `.der`, certs embedded in source strings) and
  reports the key algorithm and size/curve, signature algorithm (incl. RSA-PSS),
  subject/issuer, and expiry — **post-quantum certificates (ML-DSA / SLH-DSA)
  are recognized as already safe**, and a certificate file that fails to parse
  (or cannot even be read) is surfaced for manual review, never silently
  skipped. TLS/SSH posture checks
  flag configurations that *enable* legacy crypto — nginx/Apache/HAProxy
  SSLv3/TLS 1.0/1.1, RC4/DES/3DES and static-RSA (`TLS_RSA_`) cipher suites, and
  OpenSSH `KexAlgorithms` lists with no PQC hybrid key exchange — while
  hardening lines (`SSLProtocol all -SSLv3 -TLSv1`, `!RC4`, `no-sslv3`,
  hybrid-first kex lists) correctly stay clean. Certificates and protocol
  findings export with their proper CycloneDX 1.6 asset types
  (`certificate` with validity metadata, `protocol` with type/version).
- **Risk scoring & prioritization** — a 5-factor weighted model (data sensitivity,
  retention exposure, harvest-now-decrypt-later exposure, compliance impact,
  business impact) yields a **priority tier** and a 0–100 score from **transparent,
  tunable default weights** — a heuristic prioritizer, not a calibrated benchmark;
  sensitivity is inferred from path/deployment context, so tune the weights to your
  estate. Also emits a migration-effort estimate and a NIST PQC replacement
  recommendation (ML-KEM / ML-DSA / SLH-DSA).
  Scores are calibrated by **deployment context** — findings in test/example code
  or vendored dependencies are de-prioritized (they protect no production data),
  so the result is a ranked worklist rather than a wall of equally-urgent alerts.
- **Migration tracking** — mark each asset `open → in progress → migrated →
  accepted risk`. The dashboard shows live **migration progress** and the
  **remaining** engineering effort, so the inventory becomes a worklist, not just
  a report. Status **persists across re-scans**, so progress isn't lost when the
  codebase is scanned again.
- **Drift detection** — each scan is diffed against the previous one, so the
  dashboard flags **new findings introduced** and **findings removed** since last
  time — catching, e.g., a PR that adds a fresh RSA usage.
- **Control-gap mapping / audit evidence** — maps findings to FISMA, CISA, FedRAMP,
  SOC 2, PCI-DSS, CNSA 2.0, and NIST CSF 2.0 controls as a **control-gap view** (it
  surfaces gaps and supplies evidence for your auditor — it does **not** assert a
  self-certified "pass") with remediation guidance; exports an auditor-ready
  **JSON** (system of record) or **print-to-PDF HTML** report. The raw asset
  inventory also exports to **CSV** (filtered) for spreadsheets, SIEM, or tickets,
  and the full inventory exports as a conformance-validated **CycloneDX 1.6 CBOM**
  (Cryptography Bill of Materials) with algorithm OIDs, NIST quantum-security
  categories, and an application→algorithm dependency graph — the standards-based
  interchange format NIST/CISA reference for post-quantum migration inventories.
- **Quantum Readiness Assessment** — one command (or one dashboard click) turns a
  scan into a branded, executive-ready report: an at-a-glance quantum-posture
  grade, the cryptographic inventory by family, a prioritized worklist, the real
  top findings, a five-framework compliance gap matrix, and a phased migration
  roadmap quantified from the actual findings. Print-to-PDF HTML for the boardroom,
  or structured **JSON** for a system of record. Every number traces to live scan
  data — no sample figures — and it states its own methodology and limits.
- **CI-native scanning** — a `quantumvault` CLI scans any path and emits a
  human-readable summary or machine output: **JSON**, **SARIF 2.1.0** (for GitHub
  code-scanning / PR annotations), **CSV**, or **CBOM**. `--fail-on <severity>`
  returns a non-zero exit code so a pipeline can block PRs that introduce
  quantum-vulnerable crypto. The same SARIF is served at `GET /api/sarif.json`.
- **Auth & org scoping (self-hosted, single-tenant by design)** — scrypt-hashed
  accounts with session tokens; every scan, asset, and report is scoped to an
  organization within your own self-hosted instance; credential endpoints are
  rate-limited per client IP to blunt brute-force, and the expensive scan
  endpoints are throttled per organization. An unauthenticated demo org is seeded
  so the dashboard is populated out of the box.

## Architecture

```
web/      React 18 + TypeScript + Vite + Tailwind v4 + Recharts dashboard
server/   Express + TypeScript API
            discovery/   pattern DB, directory scanner, Git clone   (core engine)
            risk/        5-factor weighted risk scorer
            compliance/  FISMA/CISA/FedRAMP/SOC2/PCI-DSS/CNSA-2.0/NIST-CSF-2.0 report generator + HTML export
            auth/        scrypt auth, sessions, org-scoping middleware
            store/       SQLite persistence (node:sqlite — zero native deps)
            sample-target/  bundled vulnerable fixtures, scanned on first boot
.github/  CI/CD: build, unit tests, compose integration smoke-test, GHCR publish
```

Persistence uses Node's built-in `node:sqlite`, so there are **no native
dependencies** and no external database to run. The store layer is the only
thing to swap to scale out (e.g. Postgres + Elasticsearch).

## Quick start — Docker (one command)

```bash
# from the repo root
./install.sh                      # checks Docker, builds, waits for health, prints the URL
# — or, equivalently —
docker compose up --build
# dashboard: http://localhost:8080   API: http://localhost:4000
```

`./install.sh` is the friendliest path: it verifies Docker, brings the stack up,
waits until the API is healthy, and prints where to go. It starts on the free
**30-day trial** (no key needed); pass `--license UQS2.…` to license it headlessly.

The web tier (nginx) proxies `/api` to the server on the compose network. Data
persists in the `qv-data` volume. The server image bundles `git` so repo scanning
works inside the container.

### Pull pre-built images from GHCR

Every push to `main` publishes images (tagged `latest` and the commit SHA):

```
ghcr.io/uni-que-s/quantumvault-server
ghcr.io/uni-que-s/quantumvault-web
```

## Licensing & the 30-day trial

The **CLI scanner is free and open source (MIT) — forever, never gated.** The
self-hosted **platform** (dashboard, continuous monitoring, compliance reporting,
report exports) runs a **30-day trial** that starts automatically on first boot,
then asks for a license key.

- **Post-quantum & air-gapped.** License keys are signed with **ML-DSA-65
  (FIPS 204)** — the NIST post-quantum signature — and verified against a public
  key baked into the build, with **no phone-home, ever.** So the product's own
  crypto is already post-quantum (scan our repo — it's clean), and licensing works
  on a network island. Uses pure-JS `@noble/post-quantum` (no native dependency),
  so the air-gap posture holds. (Post-quantum signatures are large — keys are
  ~4.5 KB.)
- **Activate** a key in the dashboard banner, headlessly via the `QV_LICENSE`
  environment variable, or `./install.sh --license-file key.txt` (handy for the
  larger PQC keys).
- **At expiry**, a 7-day **grace** window keeps full access (with a loud renew
  banner), then the platform settles into a **read-only resting state**: your
  existing inventory stays viewable, but new scans and changes are blocked until a
  key is activated. `/api/health`, sign-in, and license activation always stay
  reachable, so an instance is never bricked. The CLI keeps working regardless.
- **Pricing** (annual, on-prem): Team, Business, and Enterprise tiers — see
  [the pricing page](https://uni-que-s.github.io/#pricing). Keys are issued per
  organization; there is no per-machine activation server to call.

## Run locally (dev)

```bash
# from the repo root
npm run install:all

# terminal 1 — API on :4000 (runs a real seed scan over sample-target on boot)
npm run dev:server

# terminal 2 — dashboard on :5173 (proxies /api to :4000)
npm run dev:web
```

Then **sign up** in the UI and **Run Scan** against either a Git repo
(`owner/repo` or an https URL) or a local absolute path. Open any asset to see its
risk breakdown and set its remediation status.

## CLI

The same engine ships as a CLI for CI pipelines and local checks:

```bash
# from the repo rootserver  (dev: npm run cli -- <args>;  built: quantumvault <args>)
npm run cli -- ./path/to/repo                 # human-readable summary
npm run cli -- ./path/to/repo --sarif > out.sarif   # GitHub code-scanning
npm run cli -- . --fail-on high               # exit 1 if any finding is >= high

# adopt in CI without failing on day-one debt: accept current findings once…
npm run cli -- . --write-baseline quantumvault-baseline.json
# …then fail only on crypto introduced AFTER the baseline:
npm run cli -- . --baseline quantumvault-baseline.json --fail-on high
```

Output formats: default table, `--json`, `--sarif` (2.1.0), `--cbom` (CycloneDX
1.6), `--csv`, and `--assessment` (a branded Quantum Readiness Assessment as
print-to-PDF HTML — pass `--org "<name>"` for the report header). `--fail-on
<critical|high|medium|low>` gates a pipeline by exit code. In CI, run the scan
with `--sarif`, upload the result to GitHub code-scanning, and add `--fail-on` to
block merges on new quantum-vulnerable crypto.

```bash
# produce the executive deliverable from a client/internal repo, no server needed
quantumvault ./repo --assessment --org "Acme Corp" > quantum-readiness.html
```

**Baseline & ratchet (recommended for CI):** `--write-baseline <file>` records
the current findings as accepted; `--baseline <file>` then makes `--fail-on` gate
only on findings that are *new* since the baseline. Fingerprints are
line-independent (moving or reindenting an accepted finding isn't "new"), and the
baseline stores opaque fingerprints only — never algorithm names — so a committed
baseline file never trips the scanner on itself. Re-run `--write-baseline` to
accept new findings deliberately. (Low-confidence "possible mentions" are never
gated.)

**Path exclusions:** for vendored or whole-directory exceptions, add a
`.quantumvaultignore` at the scan root. Each line is a repo-relative path prefix
(forward slashes); `#` lines are comments. Matching is prefix-based, not glob, so
suppression is explicit:

```
# .quantumvaultignore
third_party
legacy/keystore
config/known-accepted.pem
```

## GitHub Action

Drop QuantumVault into any repository's CI to surface quantum-vulnerable crypto
as code-scanning alerts and (optionally) gate pull requests:

```yaml
# .github/workflows/quantumvault.yml
on: [pull_request]
permissions:
  contents: read
  security-events: write   # to upload SARIF
jobs:
  crypto-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: uni-que-s/uniques@v0.3.3   # pin to a release tag (or a commit SHA)
        with:
          path: .
          fail-on: high          # optional: fail the PR on a high+ finding
          sarif-file: quantumvault.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: quantumvault.sarif
```

Inputs: `path` (default `.`), `fail-on` (`critical|high|medium|low`, empty =
never fail), `sarif-file` (default `quantumvault.sarif`), and `baseline` (path to
a committed baseline file). The action is a self-contained Docker action — no
separate install. This repo dogfoods it via the **Self-scan** workflow.

**Adopt on an existing codebase (ratchet on *new* crypto):** generate a baseline
once and commit it, then point the action at it. The build then fails only on
crypto introduced after adoption — never on pre-existing findings:

```bash
# once, locally, at the repo root — then commit quantumvault-baseline.json
quantumvault . --write-baseline quantumvault-baseline.json
```

```yaml
      - uses: uni-que-s/uniques@v0.3.3
        with:
          path: .
          fail-on: high
          baseline: quantumvault-baseline.json   # gate only on new findings
          sarif-file: quantumvault.sarif
```

## Configuration

The server reads these environment variables (all optional):

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `4000` | API listen port |
| `QV_DB_PATH` | `./data/quantumvault.db` | SQLite database file path |
| `QV_CORS_ORIGIN` | `*` | Comma-separated CORS allowlist; set to your dashboard origin(s) if the API port is exposed directly rather than proxied |
| `QV_LOG` | on | Set to `off` to silence structured (JSON-per-line) access logs |
| `QV_SEED` | | Set to `force` to re-run the sample-target seed scan on boot |
| `QV_RISK_WEIGHTS` | (built-in) | JSON object overriding any of the 5 risk-factor weights (`dataSensitivity`, `retentionExposure`, `hndlExposure`, `complianceImpact`, `businessImpact`); merged over defaults and normalized to 1.0 |

**Hardening:** the API sends conservative security headers (`nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy`, COOP), returns a JSON error envelope
that never leaks 5xx internals, drains in-flight requests on `SIGTERM`/`SIGINT`
before closing SQLite cleanly, and runs as a **non-root** user inside its
container. Private-repo access tokens are used only for the clone (passed via
git's env-based config, never on the command line) and are never persisted or
logged.

## API

Reads are open on the demo org; mutations require `Authorization: Bearer <token>`.

| Method | Path | Auth | Description |
| --- | --- | :---: | --- |
| POST | `/api/auth/signup` | | Create an org + account, returns a token |
| POST | `/api/auth/login` | | Log in, returns a token |
| GET | `/api/auth/me` | ● | Current user/org |
| GET | `/api/health` | | Service + pattern count |
| GET | `/api/openapi.json` | | OpenAPI 3.1 description of this API |
| GET | `/api/dashboard` | | Posture + migration progress for the latest scan |
| GET | `/api/risk/config` | | Active risk-scoring weights + factor descriptions |
| GET | `/api/assets` | | Discovered assets (`?family=`, `?priority=`, `?q=`) |
| GET | `/api/assets/export.csv` | | Download the inventory as CSV (honors the same filters) |
| GET | `/api/cbom.json` | | CycloneDX 1.6 Cryptography Bill of Materials for the latest scan |
| GET | `/api/sarif.json` | | SARIF 2.1.0 log of the latest scan (GitHub code-scanning) |
| GET | `/api/assessment/report.json` | | Quantum Readiness Assessment as a structured JSON model |
| GET | `/api/assessment/report.html` | | Quantum Readiness Assessment as branded print-to-PDF HTML |
| GET | `/api/assets/:id` | | Single asset with risk breakdown |
| PATCH | `/api/assets/:id/status` | ● | Set remediation status (`open`/`in_progress`/`migrated`/`accepted`) |
| POST | `/api/scans` | ● | Scan a local path `{ "target": "/abs/path" }` |
| POST | `/api/scans/git` | ● | Scan a repo `{ "url": "owner/repo", "token?": "…" }` |
| GET | `/api/scans` | | Scan history |
| GET | `/api/compliance` | | Reports for all frameworks |
| GET | `/api/compliance/:framework` | | One framework report |
| GET | `/api/compliance/:framework/export.json` | | Download JSON report |
| GET | `/api/compliance/:framework/export.html` | | Print-to-PDF HTML report |

## Testing & CI/CD

```bash
npm --prefix server test     # node:test: unit + store + HTTP API integration suite
npm --prefix web test        # vitest + Testing Library: component/UI tests
```

The server suite boots the real Express app on an ephemeral port (against an
isolated SQLite db) and drives it over HTTP — covering auth guards, org
isolation, scan → status → CSV export, and error paths — alongside unit tests for
scoring, patterns, repo normalization, the scanner, CSV escaping, and rate
limiting. The web suite renders UI components under jsdom.

GitHub Actions runs on every push/PR:

1. **server** — type-check, build, unit tests
2. **web** — type-check, build
3. **docker** — `docker compose build` + integration smoke-test (SPA shell,
   direct `/api/health`, and `/api/health` *through the nginx proxy*)
4. **publish** — push both images to GHCR (on `main` only)

## Notes & roadmap

- Remediation status **carries forward across re-scans**: a finding marked
  migrated/in-progress/accepted keeps that status when the codebase is re-scanned,
  matched by file + detection pattern + matched line (line numbers may shift).
- The risk model is a transparent, auditable weighted heuristic — not a black-box
  ML model — by design.
- **Self-hosted by design.** QuantumVault runs entirely inside your own
  environment — a single auditable service you deploy in your network or an
  air-gapped enclave. Your source code never leaves your boundary; there is no
  SaaS tier and no data egress. (This is the deliberate posture, not a
  limitation — it's the whole point for a regulated buyer.)

## Security

Found a vulnerability? Please report it privately — see
[`SECURITY.md`](SECURITY.md) for the disclosure process and our response SLA. Do
not open a public issue for security reports.

## Changelog

Release history is tracked in [`CHANGELOG.md`](CHANGELOG.md).

## License

[MIT](LICENSE).
