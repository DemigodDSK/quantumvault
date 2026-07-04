/** Single source of truth for the tool version stamped into exports (CBOM tool
 *  metadata, OpenAPI, etc.) and reported by /api/health. 0.7.0 = ENG-02
 *  certificate & TLS-configuration discovery: a zero-dependency DER/ASN.1
 *  reader (x509.ts) parses X.509 certs (PEM blocks incl. chains; binary DER
 *  under ANY cert/key extension incl. mislabeled .pem/.key; headerless base64
 *  DER in .der/.cer/.crt) into enriched assets — key algorithm + bits/curve,
 *  signature algorithm (incl. RSA-PSS params), subject/issuer CN,
 *  validity/expiry — with PQC OIDs (ML-DSA/SLH-DSA/ML-KEM) recognized as SAFE;
 *  a parsed cert replaces the generic PEM-header finding (one cert, one asset)
 *  and an unparseable OR unreadable (EACCES) cert file is surfaced for review,
 *  never silently skipped. Six TLS/SSH
 *  posture patterns (nginx/Apache/HAProxy legacy protocols + weak ciphers +
 *  static-RSA suites; OpenSSH classical-only KexAlgorithms with no PQC hybrid;
 *  53 → 59 patterns). CBOM now emits CycloneDX `certificate` and `protocol`
 *  asset types. 0.6.1 = benchmark-driven
 *  precision + corpus widened to 20 repos. Fixes for 3 general FP classes the
 *  benchmark surfaced: Python type-annotation references (`-> X`, `Union[…]`,
 *  `type[…]` — isTypeReferenceAt), INI leading-`;` comments, and EMPTY PEM blocks
 *  (BEGIN/END with no body — isEmptyPemBlockAt). Public-repo precision 92.4% (9
 *  repos) → 95.9% (20 repos, incl. 4 zero-finding negative controls); qbench 113 @
 *  1.0/1.0. 0.6.0 = INDEPENDENT
 *  BENCHMARKS (bench/): NIST SARD/Juliet CWE-327/328 recall (68/68 = 100% in-scope)
 *  + a reproducible 9-repo precision corpus (86.1% as adjudicated → 92.4% after the
 *  benchmark-driven i18n fix). Both benchmarks drove real engine fixes: SARD exposed
 *  a trailing-`\b` bug that silently dropped createHash('md5') / MessageDigest /
 *  getInstance("DES") (recall); the repo corpus exposed the i18n-placeholder FP
 *  class (a crypto name/armor in a localization catalog is UI text — `isLocale
 *  ResourceFile` downgrade). qbench 107 @ 1.0/1.0. 0.5.2 = closed two v0.5.1
 *  residual precision gaps: an ssh key-type NAME in prose (a log/label with no
 *  adjacent key bytes) now yields the never-downgrade rule (bareKeyName +
 *  proseMention — a real key line's base64 blob still protects it, and a key named
 *  in a URL path still wins per path-keymaterial-stays); and an UNQUOTED config
 *  path/route slug is downgraded like the quoted form. qbench 104 @ 1.0/1.0.
 *  0.5.1 = messy-app-code
 *  precision — file-scope crypto corroboration downgrades coincidental ambiguous
 *  shapes (a `dh.generate` on a DateHelper, `new DSA` = Delivery Service Area, a
 *  bare `des3`/`md5sum`/`pkcs12`/`.p12` token) to possible-mentions in files with
 *  no real crypto, plus disable-directive arrow/bracket forms and a non-JWK JSON
 *  tightening; qbench 100 cases at 1.0/1.0. Also completes the user-facing UniQueS
 *  rebrand (scan banner, assessment/compliance reports, SARIF driver + CBOM tool
 *  identity). 0.5.0 = POST-QUANTUM
 *  license signing — license keys are now ML-DSA-65 (FIPS 204, pure-JS
 *  @noble/post-quantum), so the product's OWN code contains no quantum-vulnerable
 *  crypto and its repo scans clean (token prefix UQS2; Ed25519/UQS1 retired).
 *  0.4.1 = grace→read-only trial enforcement + two classifier fixes
 *  (Python-docstring FP class via triple-quote spans; Java/Kotlin JOSE-alg recall
 *  via a code-context upgrade).
 *  0.4.0 = on-prem license gate + 30-day trial (offline Ed25519 signed keys, no
 *  phone-home; the platform is gated, the free CLI is not) + one-command
 *  install.sh. 0.3.10 = enum-constant
 *  reference downgrade (qbench worklist cleared). 0.3.9 = Windows-path FP cleared +
 *  Diffie-Hellman detected on config languages. 0.3.8 = URL/route-slug +
 *  disable-directive false-positive classifiers. 0.3.7 = double-count dedupe
 *  (DH/Java) + PKCS#12 + authorized_keys filename gate. 0.3.6 = recall expansion
 *  (Go/EVP/WebCrypto/X.509). 0.3.5 = mention classifier. 0.3.4 = qbench benchmark.
 *  0.3.3 = Action baseline. 0.3.2 = CI ratchet. 0.3.1 = version vis. */
export const VERSION = "0.7.0";
