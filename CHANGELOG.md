# Changelog

All notable changes to QuantumVault are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Dashboard honesty: Risk Analysis subtitle no longer says "ML-weighted".** The
  risk model is a transparent, tunable 5-factor weighted heuristic — not machine
  learning — and every other surface (README, the dashboard's own Risk Model card)
  already said so. The subtitle now reads "Transparent 5-factor scoring". Live demo
  bundle rebuilt with the corrected copy.

### Benchmark — full label coverage (no product/runtime change)

- **Public-repo precision corpus re-adjudicated to 100% label coverage.** The
  previous report labeled only the first ~60 findings per repo; the uncounted tail
  was asserted "TP-leaning" but never verified. This labels the whole tail — 650
  additional findings across the six largest repos (vault, pyca-cryptography,
  step-ca, openssh, gitea, paramiko) — each adjudicated by reading the cited source
  and every FP re-checked by an independent skeptic pass. Labels published in
  `bench/repos/labels/`.
- **Headline precision is now 88.6% (931 TP / 120 FP), full coverage, down from the
  capped 95.9%.** The number went down because the previously-hidden tail contains
  real false positives — most of them (79) bare Go `import "crypto/…"` lines in
  vault, which the benchmark's documented convention labels FP (the import is not a
  use site; the real call is labeled TP separately). We kept the convention rather
  than flip it to lift the metric. A precision number you can only quote by capping
  the sample is not a precision number. See `bench/REPORT.md` §2.
- **X.509 certificates split out of the precision denominator.** `bench/repos/run.mjs`
  now reports parsed certificates (683 across the corpus) as their own column and
  excludes them from precision — a successful DER parse is proof a cert exists, not a
  hand-adjudicated judgment. Orphaned labels whose finding no longer surfaces as
  actionable (84: 52 old cert-body TPs now parsed as certificates, 32 old FPs the
  v0.6.x demotions now correctly rank low) were pruned.
- **Next honest engine opportunity (tracked, not chased here):** demote Go
  `import`-only crypto lines to low-confidence mentions when the package's real call
  sites are surfaced separately — with a qbench guard proving `ecdsa.GenerateKey`
  still fires. This would recover most of the vault gap by fixing detection, not by
  relabeling.

## [0.7.0] - 2026-07-03

### Added

- **X.509 certificate discovery (ENG-02, part 1).** A minimal, zero-dependency
  DER/ASN.1 reader in pure TypeScript (`server/src/discovery/x509.ts`) — bounded,
  total (malformed input returns a typed failure, never throws or hangs), no
  native/WASM dependency, so the air-gapped posture is intact. Every
  `-----BEGIN CERTIFICATE-----` block (including chains — one asset per
  certificate, and certs embedded in source string literals) and every binary
  `.der`/`.crt`/`.cer` file is parsed into an enriched asset: key algorithm with
  exact modulus bits (sign-byte aware) or named curve (P-256/P-384/P-521/
  secp256k1), signature algorithm (including the RSA-PSS params hash),
  subject/issuer CN, validity window, and an expiry flag — carried as new
  optional `cert*` fields on `CryptoAsset`. **Post-quantum certificates are
  recognized as SAFE**: ML-DSA-44/65/87, SLH-DSA (all 12 parameter sets), and
  ML-KEM OIDs parse to `quantumVulnerable: false` and never gate a build or
  count against a compliance control.
- **TLS/SSH configuration posture (ENG-02, part 2).** Six new patterns (53 → 59):
  nginx `ssl_protocols`/`ssl_ciphers`, Apache `SSLProtocol`/`SSLCipherSuite`,
  HAProxy `ssl-default-bind-options`/`-ciphers`, and OpenSSH `KexAlgorithms`.
  They fire only on lines that ENABLE legacy crypto — SSLv3/TLS 1.0/1.1, RC4/
  DES/3DES suites, static-RSA (`TLS_RSA_`) key exchange, or a classical-only SSH
  kex list with no PQC hybrid. Disabling forms are recognized and stay clean:
  `SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1`, OpenSSL kill syntax (`!RC4`, killed
  compound suite names), HAProxy `no-sslv3`, `KexAlgorithms -…` removals, and a
  kex list that includes `sntrup761x25519`/`mlkem768x25519`. `sshd_config`/
  `ssh_config` (extensionless) now scan as config.
- **CBOM certificate & protocol asset types.** Certificate findings emit
  CycloneDX 1.6 `assetType: "certificate"` with `certificateProperties`
  (subjectName, issuerName, notValidBefore/After, certificateFormat); posture
  findings emit `assetType: "protocol"` with `protocolProperties` (type tls/ssh,
  version where a single one is knowable). Conformance against the official
  CycloneDX 1.6 schema is proven in CI for all three asset shapes.

### Fixed

- **Dedupe (the v0.3.7 rule, extended):** a parsed certificate REPLACES the
  generic `x509-cert-body` header finding for its block — one certificate, one
  asset — and a `KexAlgorithms …diffie-hellman-…` line fires only
  `ssh-classical-kex`, not `dh-keyexchange` too. Proven by qbench cases.
- **No silent skips:** binary DER under ANY certificate/key extension —
  `.der`/`.crt`/`.cer` and the common mislabeled exports `.pem`/`.key`
  (`openssl x509 -outform DER -out cert.pem`) — was previously dropped by the
  binary-file check; it is now parsed, and a file that fails to parse surfaces
  as a low-confidence "unparseable certificate — review manually" finding (fail
  closed: quantum-vulnerable until a human clears it). The same fail-closed rule
  covers a cert/key file the scanner cannot READ (permission/I-O error) and a
  text `.der`/`.cer`/`.crt` holding headerless base64 DER (parsed) or
  unrecognizable cert-shaped content (surfaced). A PEM block whose parse fails
  keeps the generic medium-confidence finding.
- **Killed static-RSA suites are remediation, not exposure:** the OpenSSL
  kill-syntax lookbehind now also guards the `TLS_RSA_WITH_` arm of all three
  cipher patterns — `ssl_ciphers HIGH:!TLS_RSA_WITH_AES_128_CBC_SHA` (and the
  `-` removal form, Apache and HAProxy alike) no longer fires as a
  high-confidence weak-cipher finding.
- **Long-KexAlgorithms dedupe:** the `dh-keyexchange` yield-to-`ssh-classical-kex`
  lookbehind bound was raised from 500 to 1000 chars to match the scanner's
  line-length gate, so an unusually long (but legal) kex list can no longer
  double-count one directive line as two findings.

qbench is now **136 cases at 1.0/1.0** (23 new: posture positives incl. the
HAProxy ciphers/ssl-min-ver arms and Apache/HAProxy static-RSA suites,
disabled/modern/prose/comment guards incl. killed-TLS_RSA exclusions for all
three cipher patterns, the parse-dedupe case, and the long-kex dedupe case).
`SSLProtocol all` (version-dependent SSLv3 enablement on old builds) is
documented in KNOWN_GAPS as a deliberate lexical scope boundary.

## [0.6.1] - 2026-07-01

### Changed

- **Benchmark corpus widened to 20 repositories; precision rose to 95.9%.** The
  public-repo corpus (`bench/repos/`) grew from 9 to 20 pinned repos — adding
  vault, step-ca, age, rustls, libsodium, pyjwt, requests, express, lodash,
  prometheus, and etcd, including four negative controls that produce zero findings.
  Precision **rose** as the corpus grew (92.4% on 9 → **95.9% on 20**, 446 TP / 19
  FP), which is the point: the number generalizes rather than reflecting a favourable
  sample. Per-finding labels published for all 20 in `bench/repos/labels/`.

### Fixed

Three general false-positive classes the widened benchmark surfaced — each helps any
codebase, not just these repos:

- **Python type-annotation references** — a crypto class named in a return annotation
  (`-> DSAPrivateKey:`) or a typing subscript (`Union[…, DSAPrivateKey]`,
  `type[algorithms.AES128]`) is a type, not an operation. New `isTypeReferenceAt`
  (scoped to Python; the `Union`/`type` keyword, not a bare bracket, is what proves
  it — a list literal `[RS256, ES256]` of real algorithm constants is untouched).
- **INI leading-`;` comments** — a `;; openssl pkcs12 …` example in a `.ini`/config
  file is documentation, not config. Config-language comment masking now recognizes
  a line-leading `;` (scoped so a `;` statement-separator or in-value `;` is safe).
- **Empty PEM blocks** — a `-----BEGIN CERTIFICATE-----` immediately followed by
  `-----END-----` with no base64 body is a negative/error test placeholder, not a
  certificate. New `isEmptyPemBlockAt` downgrades it (allowed to override the
  key-material never-downgrade rule, since an empty block holds nothing).

The remaining benchmark false positives (Go import lines — arguably true positives;
pyca `isinstance` tuples; openssh denylist/log-string; a jsonwebtoken template) are
a diverse niche tail, deliberately left rather than overfit to the sample, and are
documented + measured in `KNOWN_GAPS`. qbench is now **113 cases at 1.0/1.0**.

## [0.6.0] - 2026-07-01

### Added

- **Independent, reproducible benchmarks (`bench/`).** Two external accuracy
  measurements, so the numbers we quote are auditable rather than self-graded — with
  a written scope boundary and a `qbench`-is-a-gate-not-a-benchmark disclaimer:
  - **NIST SARD / Juliet** (`bench/sard/`): recall against the official U.S. NIST
    Software Assurance Reference Dataset (CWE-327 broken crypto, CWE-328 reversible
    hash). **68/68 = 100% in-scope recall** (DES / 3DES / MD5 / SHA-1). Honest scope:
    Juliet is the *classical* threat model and contains no RSA/ECC — a high score
    there is necessary, not sufficient, for PQC-discovery quality.
  - **Reproducible public-repo corpus** (`bench/repos/`): precision on nine pinned,
    well-known repositories (caddy, gitea, gin, openssh, jjwt, node-jsonwebtoken,
    pyca/cryptography, paramiko, syncthing), every actionable finding hand-labeled
    TP/FP against the cited source and adversarially re-verified, with the labels
    published for audit. **86.1% precision as independently adjudicated → 92.4%**
    after the fix below. A framework that delegates crypto (gin) returns **0
    findings — the negative control**.

### Fixed

- **NIST SARD exposed a real recall bug (now fixed):** three patterns had a trailing
  `\b` that a closing quote can never satisfy, silently dropping `createHash('md5')`,
  `MessageDigest.getInstance("MD5"/"SHA-1")`, and Java `getInstance("DES")` — plus a
  `"SHA1"`-vs-`"SHA-1"` mismatch. `hash-md5-sha1` and `sym-des-3des` restructured so
  call-shape arms don't require a trailing boundary; DES-via-getInstance added.
  qbench never caught these because we never wrote those exact fixtures — the case
  for an external corpus, in one result.
- **The repo corpus exposed the i18n false-positive class (now fixed):** a crypto
  name or key-armor header inside a **localization catalog** (`options/locale/
  locale_*.json` etc.) is UI placeholder text, not a use or a real key — and it
  dominated gitea's FPs across every non-English locale, where the Latin-only prose
  rule couldn't recognize the surrounding text. New `isLocaleResourceFile` downgrades
  matches in translation catalogs to possible mentions (real keys never ship in a
  locale file). gitea precision rose 58.3% → 94.6%.

Remaining benchmark FP classes (type annotations, prose in interpolated templates,
denylist-removal calls, INI `;` comments) are documented and measured in
`KNOWN_GAPS`, not gated. qbench is now **107 cases at 1.0/1.0**.

## [0.5.2] - 2026-07-01

### Fixed

- **An ssh key-type NAME in prose is no longer flagged as key material.** `ssh-rsa`
  / `ecdsa-sha2-nistp256` appearing in a natural-language log or label ("redacted an
  ssh-rsa entry from the audit output"), with no adjacent base64 key bytes, is a
  name reference — the never-downgrade rule now yields for it (`bareKeyName` +
  `proseMention`). A real key line still carries the blob (so it stays actionable),
  and a key type named in a URL/route path (`/keys/ssh-rsa/import`) still wins the
  never-downgrade rule — that deliberate decision is preserved.
- **An unquoted config path/route slug is now downgraded like the quoted form.** An
  unquoted YAML/Terraform value that is a URL or route (`rotate:
  /api/v2/diffie-hellman/rotate`) names an endpoint, not a key exchange; it is not a
  string span, so the path classifier previously missed it. A bare algorithm value
  (`keyExchange: diffie-hellman`) is not a path and still fires.

These close two of the three residual gaps documented in v0.5.1's `KNOWN_GAPS`;
qbench is now **104 cases at 1.0/1.0**. The last gap — a coincidental ambiguous
shape that shares a *file* with real crypto — needs call-vs-object data flow
(ENG-01b) and remains tracked, not gated.

## [0.5.1] - 2026-07-01

### Changed

- **Messy-app-code precision — file-scope crypto corroboration.** A crypto *shape*
  that is lexically identical to an ordinary application identifier — `dh.generate()`
  on a DateHelper, `new DSA(zone)` for a "Delivery Service Area", a bare
  `des3`/`aes_128`/`md5sum`/`pkcs12` token, a `report.p12` filename — is now
  downgraded to a **possible mention** unless the file shows a real cryptographic
  signal (a crypto import, a PEM block, a curve/key-size, an unambiguous primitive).
  Real crypto files corroborate, so recall is preserved — verified: caddy's
  production ECDSA/RSA findings and every qbench positive still fire. A field
  measurement across ten languages found a **43% false-positive rate (64/149) on
  coincidental identifiers** before this change; the ambiguous-shape class is now
  cleared in non-crypto files. qbench is **100 cases at 1.0/1.0** (19 new). The
  honest residual — a coincidence that shares a *file* with real crypto — needs
  call-vs-object data flow (ENG-01b) and is tracked, measured, and NOT gated
  (see `KNOWN_GAPS`).
- **Completed the user-facing UniQueS rebrand.** The scan-summary banner, the
  branded assessment and compliance reports, the SARIF `tool.driver.name`, and the
  CBOM `metadata.tools[].name` now read **UniQueS** (the CLI `--help` banner already
  did). Internal identifiers — the `quantumvault` service id, `QV_*` env vars, the
  package name — are unchanged.

### Fixed

- **Disable-directive detection now covers the C# indexer (`["ssh-rsa"] = false`)
  and the PHP/JS arrow (`'ssh-rsa' => false`) forms** — an explicitly turned-off
  algorithm is remediation, not a live posture, and is downgraded even for key
  material.
- **A JSON object with `"kty":"EC"` but no JWK companion field** (crv/x/y/n/e/kid)
  is a coincidental descriptor, not a JWK, and no longer flags as key material.
- **Web container healthcheck now targets `127.0.0.1`, not `localhost`.** On
  `nginx:alpine`, `localhost` resolves to `::1` first while nginx binds IPv4 only,
  so the dashboard container reported `unhealthy` while serving correctly.

## [0.5.0] - 2026-07-01

### Changed

- **Post-quantum license signing** — the product now signs its own license
  keys with **ML-DSA-65 (FIPS 204)**, the NIST post-quantum lattice signature —
  replacing the Ed25519 (elliptic-curve) signing used in v0.4.x. The consequence
  is the point: **UniQueS's own codebase now contains no quantum-vulnerable
  cryptography, so scanning our repo comes back clean** (we eat our own dog food —
  the only crypto scanner whose own product is already post-quantum). Uses
  **`@noble/post-quantum`** — a pure-JS implementation, **no native/WASM
  dependency**, so the zero-native-dependency / air-gap posture is fully
  preserved and licensing still works offline with no phone-home. Token prefix is
  now `UQS2`; pre-1.0 `UQS1` (Ed25519) keys are no longer accepted. Post-quantum
  signatures are large, so license keys are now ~4.5 KB (the dashboard key box is
  a textarea; `install.sh` accepts `--license-file`). The 32-byte signing seed
  (`server/.license-signing-seed`, gitignored) deterministically regenerates the
  keypair for the founder-only issuer.

## [0.4.1] - 2026-06-30

### Added

- **Grace → read-only trial enforcement** — instead of a hard lock at
  expiry, the platform now gives a **7-day grace window** (full access, loud renew
  banner) and then settles into a **read-only resting state**: a lapsed buyer can
  still *view* their existing inventory (GET), but new scans and mutations are
  gated (402). Seeing your own crypto exposure converts better than a wall. Tunable
  via `QV_GRACE_DAYS`; health/auth/license stay open; the CLI is unaffected.

### Fixed

- **Two field-precision classifier gaps (v0.4.1)** — surfaced by a precision scan
  of real OSS repos and fixed with qbench staying 100%/100% (now 80 cases):
  - **Python-docstring false positives** — a crypto name inside a `"""…"""`
    docstring (e.g. paramiko's "…uses Diffie-Hellman…") was ranked actionable
    because the tokenizer reset at the first newline. `lexStringSpans` /
    `maskComments` now recognize triple-quoted strings, so docstring crypto is a
    low-confidence mention (incl. key-material tokens like `ssh-rsa` named only as
    a doc example — the never-downgrade rule now yields inside a docstring).
  - **Java/Kotlin JOSE-alg recall** — a pure RSA/ECDSA signing library (jwtk/jjwt)
    reported **zero** exposure because `RS256`/`ES256` are base-low (to avoid
    flagging `["RS256"]` config labels). A bare JOSE-alg token in *code* (a typed
    constant declaration `SignatureAlgorithm RS256 = …`) is now upgraded to
    actionable, while a string-value label stays a low mention — jjwt goes from 0
    to 60 actionable findings.

### Added

- **On-prem license gate + 30-day trial (v0.4.0 milestone — shipped in the 0.4.1 release; no separate 0.4.0 tag)** — the commercial v0.1 of the
  product. The self-hosted **platform** (dashboard, scans, compliance, monitoring,
  exports) now runs a 30-day trial that auto-starts on first boot, then locks with
  a clear in-app prompt until a license key is activated. Keys are **offline
  Ed25519 signed tokens** verified against an embedded public key — **no
  phone-home**, so it works air-gapped, consistent with "your source never leaves
  your network." The **free CLI scanner is never gated**. New: `GET /api/license`
  + `POST /api/license/activate`, a dashboard trial/renewal banner, headless
  activation via `QV_LICENSE`, founder-only `scripts/gen-license-keypair.ts` +
  `scripts/issue-license.ts`, and a one-command `./install.sh`. The trial clock is
  the local DB volume (an accepted v0.1 limit — the signed key, not the trial, is
  the control for paid use). Enforcement is a graceful soft-lock; health/auth/
  license endpoints stay reachable so an instance is always recoverable by
  entering a key.

## [0.3.10] - 2026-06-29

_Consolidates the incremental 0.2.1–0.3.10 releases; see the matching git tags
for exact per-version dates. Each entry below is tagged inline with the version
it shipped in._

### Added

- **Enum-constant references downgraded — precision worklist cleared (v0.3.10)** —
  the zero-dependency stand-in for the call-vs-reference data flow a full AST would
  give, and the final qbench worklist gap. A bare read of an algorithm enum/class
  constant (`const x = SignatureAlgorithm.DSA`, `if (algo == SignatureAlgorithm.DSA)`)
  names the primitive but does not perform the operation, so it is a possible
  mention, not exposure. Scoped narrowly so it cannot swallow a real use: the match
  text itself must be `Receiver.CONSTANT` (which excludes `dsa.generate`,
  `RSA.Create`, and bare-token matches), it must not be an invocation, and it must
  sit in assignment/comparison position — an argument-position use
  (`signWith(SignatureAlgorithm.DSA, key)`) keeps its confidence and still fires.
  With this the qbench precision worklist is **empty**: every gap surfaced since the
  benchmark was introduced is resolved and gated (77 cases at 1.0/1.0). The full
  tree-sitter AST (ENG-01b) is not needed for the known gaps; it stays in reserve
  if a future gap genuinely requires data flow.

### Fixed

- **Comment-masking no longer leaks across lines from a regex literal (v0.3.10)** —
  the comment masker tracked `'`/`"` string state without resetting at end-of-line,
  so a regex containing a quote character (e.g. `str.replace(/^["']+/g, "")`) opened
  a "string" that never closed and left every following line unmasked — exposing
  later **comments** to pattern matching and producing false positives. Since a
  `'`/`"` literal cannot span a newline in JS/TS, the masker (and the string-span
  lexer) now reset that state at the line break; template literals (backticks) still
  span lines. Found by the v0.3.10 self-scan and covered by a regression case.
- **Windows-path false positive cleared + Diffie-Hellman detected in config (v0.3.9)**
  — closes the last lexical precision-worklist gap and a recall miss. The path
  classifier now also recognizes **Windows drive paths** (`"C:\\certs\\diffie-hellman.pem"`,
  `C:/…`), so a crypto name that is a backslash-path segment is a possible mention,
  not a use (key material in a path still stays actionable). And **`dh-keyexchange`
  now runs on config languages** (YAML/JSON/Terraform/conf): a real key-exchange
  config naming `diffie-hellman` (e.g. `keyExchange: diffie-hellman`) was previously
  invisible and is now detected as a medium finding — while the per-occurrence
  classifier keeps it honest (a disabled directive `diffie-hellman: false`, a
  route/URL slug, a `#`/`//` comment, or a prose mention all downgrade to a possible
  mention). After this, the qbench precision worklist is down to a single gap —
  reading an enum member (`SignatureAlgorithm.DSA`) — which needs call-vs-reference
  data flow (ENG-01b / tree-sitter AST); the zero-dependency lexical-classifier rung
  is exhausted. Corpus now 70 gated cases at 1.0/1.0.
- **URL/route slugs and disable directives no longer over-flag (v0.3.8)** — two
  more false-positive classes the zero-dependency lexical classifier can now
  resolve, keeping the air-gapped posture intact. A crypto name that is a **URL or
  route path slug** (`"/api/v2/diffie-hellman/rotate"`,
  `"https://host/v2/diffie-hellman/rotate"`) names an endpoint, not a use, so it
  is downgraded to a possible mention — while a Go module import (`"crypto/rsa"`,
  no leading slash, no scheme) and a real call sharing the line still fire. A
  crypto key type explicitly **disabled** in config (`"ssh-rsa": false`,
  `ssh-rsa: off`, `"dsa": "disabled"`) is remediation, not exposure: an explicit
  disable is the one signal allowed to override the never-downgrade rule for key
  material, because a turned-off algorithm is not a live exposure. Allow-listed
  (`["ssh-rsa"]`) and enabled (`"ssh-rsa": true`) values still fire. Two cases
  moved from the qbench worklist into the gated corpus (now 63 cases at 1.0/1.0);
  the lone remaining gap — reading an enum member (`SignatureAlgorithm.DSA`) —
  needs call-vs-reference data flow and is the marker for ENG-01b (tree-sitter
  AST), the locked-last precision rung.
- **Dedupe double-counts + PKCS#12 + SSH key files (v0.3.7)** — one construct no
  longer counts twice: `DH_generate_key` was matched by both `dh-openssl-c` and
  `dh-keyexchange`, and a chained `getInstance("RSA").generateKeyPair()` by both
  `rsa-java-keypairgen` and `rsa-keygen-openssl`; each now reports once (the
  redundant arms were removed at the source). New: **PKCS#12 keystores**
  (`.pfx`/`.p12`, `pkcs12.Decode`), and well-known **SSH key files with no
  extension** (`authorized_keys`, `known_hosts`, `id_*.pub`) are now scanned
  (they were skipped by the extension map). Pattern count 52 → 53.
- **Recall expansion — formerly-missed real crypto now detected (v0.3.6)** —
  five qbench-confirmed false negatives are fixed: **Go ECDSA** (`crypto/ecdsa` /
  `ecdsa.GenerateKey`) and **Go DSA** (`dsa.GenerateKey`, which the case-sensitive
  matcher missed), **OpenSSL `EVP_PKEY_keygen`** (the 3.x generic keygen),
  **Web Crypto ECDSA/ECDH** (`name: "ECDSA"` — was only a low curve-name mention),
  and **X.509 certificate bodies** (`-----BEGIN CERTIFICATE-----` — real RSA/ECC
  public key + signature). Pattern count 47 → 52; the cases moved from the qbench
  worklist into the gated corpus.
- **Mention classifier — label / log / identifier false positives downgraded
  (v0.3.5)** — the per-occurrence classifier now treats a crypto name inside a
  *label or message* string (≥2 words with a natural-language word, e.g.
  `"3DES weak"`, `"Diffie-Hellman handshake failed"`, `"AES128 disabled"`,
  `"ssh-dss key rejected"`) as a **possible mention**, not exposure — generalizing
  the old prose rule (which needed ≥3 words and a function word). Structured crypto
  values keep their confidence: cipher lists, SSH key lines, and single tight
  tokens (`"RSA-OAEP"`, `"diffie-hellman"`, `"des-ede3-cbc"`) carry no
  natural-language word, and real call-sites anchor in code. Also fixed
  `sym-des-3des` to require a trailing word boundary, so an identifier like
  `TripleDESLegacyAdapter` or env var `TRIPLEDES_DISABLED` no longer matches.
  These cases moved from the qbench worklist into the gated corpus (precision/
  recall held at 1.0).
- **`qbench` precision benchmark + precision/recall fixes (v0.3.4)** — a labeled
  corpus + harness scores detection **precision and recall** over real call-sites
  and known traps, gating regressions at 1.0 on every build ("more precise on
  every build" as a tracked metric), with a worklist of known gaps. Building it,
  plus an adversarial probe of 34 CLI-verified cases, surfaced and **fixed** real
  gaps: four key-material formats that were silently missed are now detected —
  **OpenSSH private keys** (the default `ssh-keygen` output), **encrypted PKCS#8**,
  **PGP public blocks**, and **JWK** (`"kty":"RSA"`/`"EC"`); and a PQC
  certificate (`signatureAlgorithm: ML-DSA-…`, or a `dilithium.pem` path) is no
  longer mislabeled "RSA (X.509)" (the `tls-rsa-cert` matcher was greedily
  matching unrelated "RSA" on the line / asserting RSA for any cert path).
  Pattern count 43 → 47. Remaining verified gaps (string/identifier false
  positives, overlapping-pattern double-counts, and uncovered APIs like Go
  ECDSA/DSA and Web Crypto ECDSA) are tracked in the benchmark worklist.
- **GitHub Action supports the baseline ratchet + "adopt in CI" docs (v0.3.3)** —
  the published Docker action gains a `baseline` input, so `fail-on` gates only on
  findings new since a committed baseline. README now has a copy-pasteable
  workflow for adopting QuantumVault on an existing codebase (generate a baseline
  once, commit it, gate on new crypto thereafter). Verified end-to-end through the
  built action image.
- **CI baseline / ratchet (v0.3.2)** — adopt QuantumVault in CI without failing
  the build on day-one debt. `--write-baseline <file>` records the current
  findings as accepted; `--baseline <file>` then gates (with `--fail-on`) only on
  findings that are **new** since the baseline. Fingerprints are
  **line-independent** (derived from file + pattern + algorithm + normalized
  snippet), so moving or reindenting an accepted finding doesn't flag it as new.
  The baseline stores **opaque fingerprints only** — never readable algorithm
  names — so a committed baseline file never trips the scanner on itself.
  Relatedly, `--fail-on` now ignores low-confidence "possible mentions"
  (consistent with the report), so a mention can no longer fail a build.
- **CBOM conformance proven against the official CycloneDX 1.6 schema** — the
  emitted CBOM is now validated against the bundled official `bom-1.6.schema.json`
  (plus its SPDX + JSF references) in CI, turning "standards-compliant" from a
  claim into a checkable fact. The runtime keeps its fast, dependency-free
  `validateCbom()` structural guard; full JSON-Schema conformance runs as a test
  with **ajv as a dev dependency only**, so the shipped runtime stays
  zero-extra-dependency. Schemas are vendored so validation runs fully offline (no
  network in CI), consistent with the air-gapped posture.
- **Version visibility + provenance (v0.3.1)** — a self-hosted instance now shows
  which build it is running: `GET /api/health` returns `version`, and the
  dashboard sidebar displays it (the backend's version, so a stale container
  serving old code is visible at a glance). Every Quantum Readiness Assessment is
  stamped "Generated by QuantumVault v<version>" for audit provenance. Strictly
  offline — no phone-home / new-release check, in keeping with the air-gapped
  posture. The dashboard falls back to the web build version if the backend is
  unreachable or predates the field.
- **Per-occurrence context classifier (v0.3.0, ENG-01a)** — confidence is now
  refined by the *syntactic context of each match*, not just the pattern that
  fired. A crypto name embedded in a **natural-language string** (a log line,
  error, or doc — e.g. `"migrating away from diffie-hellman and 3DES"`) is
  reclassified as a **low-confidence possible mention** instead of counted
  exposure. "Prose" is gated on the presence of an English function word, so a
  *structured* crypto value with no prose — an SSH key line
  (`"ssh-rsa AAAA… user@host"`), an OpenSSL cipher list, a tight identifier
  (`"RSA-OAEP"`) — is **not** downgraded, and neither is a real call
  (`createDiffieHellman(2048)`), including one inside a template-literal
  interpolation (`` `…${createDiffieHellman(2048)}…` ``). Every occurrence on a
  line is scanned, so a prose mention can't mask a real same-line call. Value-
  bearing patterns (PEM/PGP key blocks, SSH key types, X.509 signature
  algorithms) are real wherever they appear and are never downgraded. The
  classifier is a **zero-dependency lexical pass** — no parser, no new deps,
  preserving the air-gapped single-binary posture. It can only *reclassify* a
  finding as a possible mention, never fabricate or upgrade one; the policy lives
  in one tunable function (`resolveConfidence`). Hardened against a 4-lens
  adversarial review (recall / tokenizer / offset / honesty) that caught — and
  drove fixes for — six recall regressions before release. This is the honest
  down-payment on full AST/call-site detection (ENG-01b).
- **Per-finding confidence score (v0.2.5)** — every detection now carries a
  confidence level: **high** (a library call-site or key material — e.g.
  `mbedtls_rsa_gen_key(`, `getInstance("RSA")`, a PEM block), **medium** (a
  name/config token), or **low** (a bare algorithm name/number in a string, enum,
  or doc — a likely *mention*, not a usage). **Low-confidence "possible mentions"
  are surfaced separately and excluded from the posture grade and the headline
  quantum-vulnerable count**, so a config like `["RS256","ES256"]` no longer reads
  as hard exposure. The CLI splits the count, the CBOM carries
  `quantumvault:confidence`, and the dashboard shows a "Possible Mentions" stat +
  a "mention" chip in the inventory. (This is the honest middle step toward full
  AST/semantic detection — it flags the regex engine's known weakness rather than
  hiding it.)

### Fixed

- **A clean scan is now 100% compliant for every framework (v0.2.4)** — inventory
  controls (CISA `PQC-1`, FedRAMP `CM-8`, NIST-CSF `ID.AM-02`) were marked **gap**
  when a scan found zero crypto, which dragged CISA/FedRAMP to "83% Partial" and
  NIST-CSF to 90% on a clean codebase. But a clean scan **is** a complete (empty)
  inventory — a report only exists because a scan ran — so inventory controls now
  pass. A codebase with no quantum-vulnerable crypto is a perfect 100% pass across
  all seven frameworks. Test extended to cover every framework on a clean scan.

### Changed

- **Grade reflects production code, not fixtures (v0.2.3)** — the scanner now
  skips **non-production directories** by default (`test`/`tests`/`__tests__`,
  `examples`, `samples`, `fixtures`, `mocks`, `demo`, and `sample-*`/`test-*`
  prefixes), plus tooling dirs (`.claude`, `.idea`, `.vscode`). Without this, a
  healthy repo could be graded "F" on its own test inputs — the worst first
  impression a security tool can make. A real scan target (firmware, an app) is
  unaffected. Added a regression test.
- **On-prem positioning** — the README now leads with the wedge ("find your
  quantum-vulnerable crypto and produce the CBOM regulators require — on-prem, so
  your source never leaves your network"), frames single-tenant self-host as the
  intended posture, and removes the "hosted deployment" SaaS line.
- **Detection precision + honesty (v0.2.2)** — in response to an adversarial
  red-team review:
  - **Comment masking** — the scanner now matches against a comment-stripped view
    of each file, so a crypto name in a `//`, `#`, or `/* */` comment is treated as
    a *mention*, not a *use*, and no longer fires. String literals are preserved, so
    real uses (`getInstance("RSA")`, JWT alg values, PEM blocks) still fire. Added a
    precision regression test. (Eliminating *string*-mention false positives needs
    semantic/AST detection — tracked as a follow-on.)
  - **No self-asserted "pass"** — compliance output is reframed as **control-gap /
    audit evidence**: reports are titled "Control-Gap Report," the passing state
    renders as "No gaps found," and a disclaimer states it is evidence for review,
    not a certification of compliance.
  - **Honest risk-model framing** — the README now labels the 0–100 score as a
    heuristic prioritizer from transparent, **tunable default** weights (not a
    calibrated benchmark), with sensitivity inferred from path/deployment context.
  - **README accuracy** — corrected the stale "34-pattern" claim to 43.

### Added

- **Embedded C/C++ firmware crypto detection (v0.2.1)** — the scanner now natively
  detects the firmware staples of long-life embedded systems: **mbedTLS**
  (`mbedtls_rsa_*`, `mbedtls_ecdsa_*`, `mbedtls_ecdh_*`, `mbedtls_dhm_*`),
  **wolfSSL / wolfCrypt** (`wc_MakeRsaKey`, `wc_ecc_make_key`, …), and the
  **OpenSSL C API** (`EVP_PKEY_CTX_set_rsa_keygen_bits`, `EC_KEY_new_by_curve_name`,
  `DH_generate_key`, …). Adds common C++ extensions (`.cc`, `.cxx`, `.hpp`, `.hh`)
  to the scanned set. Pattern count: 35 → 43. Targets the automotive (UN R155/R156),
  medical (FDA §524B), and defense (CNSA 2.0 firmware-signing) PQC mandates.
- **Deeper CBOM & standards export (v0.2.0 milestone)** — the CycloneDX 1.6
  Cryptography Bill of Materials now carries algorithm **OIDs** (RSA/ECC/DSA/DH,
  registry-verified), `cryptoFunctions`, `classicalSecurityLevel`, elliptic
  `curve`, and a graded NIST quantum-security **category** (0–6) per finding; it
  emits a `dependencies` graph linking the scanned application to every
  discovered algorithm; and it uses **content-addressed, deterministic** bom-refs
  and serial number, so re-scanning the same code yields a diffable BOM. A new
  `validateCbom()` conformance check (sharing one set of spec enums with the
  emitter) lets the output be *proven* CycloneDX-1.6-valid, not just asserted.
  Ambiguous lumped patterns (DES/3DES, MD5/SHA-1, Ed25519/X25519) deliberately
  withhold a specific OID rather than overclaim.
- **Two new compliance frameworks** — **CNSA 2.0** (NSA Commercial National
  Security Algorithm Suite — the PQC mandate: ML-KEM-1024 / ML-DSA-87 /
  AES-256 / SHA-384+) and **NIST CSF 2.0** (cryptographic-inventory and
  data-protection subcategories) join FISMA/CISA/FedRAMP/SOC 2/PCI-DSS. Reports,
  JSON/HTML exports, and the dashboard pick them up automatically.

- **Quantum Readiness Assessment** — QuantumVault now generates its flagship
  executive report directly from a scan, instead of hand-filling a template. The
  report computes an at-a-glance quantum-posture grade (the same model the
  dashboard surfaces), a cryptographic inventory by family with quantum-impact
  classification and NIST replacements, a priority distribution, the real top
  findings (production paths first), a five-framework compliance gap matrix, and a
  phased migration roadmap quantified from the actual critical/high/medium counts.
  - CLI: `quantumvault <path> --assessment [--org "<name>"]` emits the branded,
    print-to-PDF HTML — no server required.
  - API: `GET /api/assessment/report.html` (branded HTML) and
    `GET /api/assessment/report.json` (structured model), org-scoped; `404` until
    the org has a scan. Both are listed in the OpenAPI document.
  - Dashboard: a "Quantum Readiness Assessment" action on the Compliance page
    opens the report in a new tab, ready to print or save as PDF.
  - Every figure traces to live scan data (no sample numbers), all dynamic values
    are HTML-escaped, and the report states its own methodology and limits.
- **Zero-install live demo** — a static build of the dashboard (`npm --prefix web
  run build:demo` → `docs/demo/`) that runs entirely client-side on GitHub Pages,
  serving baked fixtures from a real scan of popular OSS libraries. Gated behind a
  compile-time flag so the demo code and fixture are dead-code-eliminated from the
  normal build. Linked from the landing page ("See it live — no install").

### Fixed

- Compliance report lookups are now case-insensitive on the framework name, so
  the `FedRAMP` report and its JSON/HTML exports resolve correctly (previously a
  naive upper-casing 404'd `FedRAMP`, whose stored name is mixed-case).

## [0.1.0] - 2026-06-11

First public release. QuantumVault closes the full
**discover → prioritize → track → prove compliance** loop for the
"harvest-now, decrypt-later" threat to RSA/ECC cryptography.

### Added

- **Cryptographic asset discovery** — a 34-pattern, language-agnostic scanner
  detecting RSA, ECC (incl. Ed25519/X25519), DSA, Diffie-Hellman, legacy
  symmetric (DES/3DES/AES-128), broken hashes (MD5/SHA-1), private-key PEMs
  (incl. PGP blocks), JWT/JOSE signing algorithms, Web Crypto RSA, SSH key types
  in IaC, language-specific key APIs (Java, Ruby, PHP, Rust, Go, Python), and
  RSA X.509 certs across 25+ file types. Scans a local path or shallow-clones a
  public or private Git repo (GitHub/GitLab/Bitbucket).
- **Risk scoring & prioritization** — a transparent 5-factor weighted model
  (data sensitivity, retention exposure, harvest-now-decrypt-later exposure,
  compliance impact, business impact) producing a 0–100 score, a priority tier,
  a migration-effort estimate, and a NIST PQC replacement recommendation
  (ML-KEM / ML-DSA / SLH-DSA). Weights are tunable per deployment via
  `QV_RISK_WEIGHTS` and surfaced on the dashboard.
- **Executive quantum-posture grade** on the dashboard.
- **Migration tracking** — per-asset remediation status
  (`open → in_progress → migrated → accepted`) that **persists across re-scans**,
  matched by file + pattern + matched line.
- **Drift detection** — each scan is diffed against the previous one, flagging
  findings introduced and removed since the last run.
- **Baselining** — a `.quantumvaultignore` file at the scan root excludes
  vendored or accepted paths so `--fail-on` isn't tripped by known exceptions.
- **Compliance automation** — maps findings to FISMA, CISA, FedRAMP, SOC 2, and
  PCI-DSS controls with pass/gap/fail status and remediation guidance; exports
  auditor-ready JSON and print-to-PDF HTML reports.
- **Exports** — CSV inventory (filtered), SARIF 2.1.0 for GitHub code-scanning,
  and a CycloneDX 1.6 CBOM (Cryptography Bill of Materials).
- **CI-native CLI** — `quantumvault` scans any path with table / `--json` /
  `--sarif` / `--cbom` / `--csv` output and `--fail-on <severity>` to gate
  pipelines by exit code.
- **GitHub Action** — self-contained Docker action (`uni-que-s/uniques`)
  that emits SARIF for code-scanning and optionally gates pull requests; this
  repo dogfoods it via a self-scan workflow.
- **Server API** — Express + TypeScript with auth (scrypt + session tokens),
  per-org multi-tenancy, per-IP credential rate limiting, per-org scan
  throttling, OpenAPI 3.1 description, and conservative security headers.
- **Web dashboard** — React 18 + TypeScript + Vite + Tailwind v4 + Recharts.
- **Persistence** — Node's built-in `node:sqlite`, so there are no native
  dependencies and no external database to run.
- **Packaging** — `docker compose` one-command stack and pre-built GHCR images
  (`ghcr.io/uni-que-s/quantumvault-server`, `-web`) published on every push to
  `main`.

### Security

- Private-repo access tokens are used only for the clone (via git's env-based
  config, never on the command line) and are never persisted or logged.
- The API runs as a non-root container user, drains in-flight requests on
  `SIGTERM`/`SIGINT`, and returns a JSON error envelope that never leaks 5xx
  internals.

[Unreleased]: https://github.com/uni-que-s/uniques/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/uni-que-s/uniques/releases/tag/v0.1.0
