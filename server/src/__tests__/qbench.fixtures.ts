/**
 * qbench — the QuantumVault precision benchmark corpus.
 *
 * A labeled set of source snippets that pins down what "precise detection" means
 * for this product: real cryptographic USES that must fire as actionable
 * exposure (high/medium confidence), and traps — crypto names in comments,
 * prose, identifiers, quantum-safe algorithms, enums — that must NOT count as
 * exposure (clean, or surfaced only as low-confidence "possible mentions").
 *
 * The harness (qbench.test.ts) scans every case and scores precision/recall over
 * *actionable* findings (the numbers a buyer sees), gating regressions. This is
 * the "more precise on every build" contract: the engine must keep getting every
 * case right, and new precision work adds cases here.
 *
 * `expect` lists the patternIds that must fire as ACTIONABLE. An empty array
 * means the case must produce NO exposure. Cases the engine does NOT yet get
 * right live in KNOWN_GAPS (below) — the precision worklist, tracked but not
 * gated, so a clean 1.0 gate stays honest.
 */
export interface QCase {
  id: string;
  ext: string;
  code: string;
  expect: string[];
  why: string;
  /** For KNOWN_GAPS only: "fp" = should be clean but the engine over-flags;
   *  "fn" = a real use the engine misses. Lets the gaps check detect a resolved
   *  gap without coupling to a specific (future) patternId. */
  gapKind?: "fp" | "fn";
}

export const QBENCH: QCase[] = [
  // ─────────────────────────────── real uses (must fire as actionable) ──────
  { id: "node-rsa-keygen", ext: "ts", expect: ["rsa-keygen-openssl"], why: "Node RSA key generation call-site",
    code: `const key = generateKeyPairSync("rsa", { modulusLength: 2048 });\n` },
  { id: "node-ecdh", ext: "ts", expect: ["ecc-node-ecdh"], why: "Node ECDH call-site",
    code: `const ecdh = createECDH("prime256v1");\n` },
  { id: "node-dh", ext: "ts", expect: ["dh-keyexchange"], why: "classical Diffie-Hellman call-site",
    code: `const dh = createDiffieHellman(2048);\n` },
  { id: "py-rsa", ext: "py", expect: ["rsa-python-cryptography"], why: "Python cryptography RSA",
    code: `priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n` },
  { id: "py-ecc", ext: "py", expect: ["ecc-python"], why: "Python cryptography EC keygen",
    code: `k = ec.generate_private_key(ec.SECP256R1())\n` },
  { id: "java-rsa", ext: "java", expect: ["rsa-java-keypairgen"], why: "Java KeyPairGenerator RSA",
    code: `KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\n` },
  { id: "java-dsa", ext: "java", expect: ["dsa-java-keypairgen"], why: "Java KeyPairGenerator DSA",
    code: `KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");\n` },
  { id: "dotnet-rsa", ext: "cs", expect: ["rsa-dotnet"], why: ".NET RSA.Create",
    code: `var r = RSA.Create(2048);\n` },
  { id: "go-rsa", ext: "go", expect: ["go-crypto-rsa"], why: "Go crypto/rsa import",
    code: `import "crypto/rsa"\n` },
  { id: "swift-p256", ext: "swift", expect: ["ecc-swift-cryptokit"], why: "Swift CryptoKit P256",
    code: `let key = P256.Signing.PrivateKey()\n` },
  { id: "mbedtls-rsa", ext: "c", expect: ["rsa-mbedtls"], why: "mbedTLS firmware RSA keygen",
    code: `mbedtls_rsa_gen_key(&ctx, rng, NULL, 2048, 65537);\n` },
  { id: "wolfssl-ecc", ext: "c", expect: ["ecc-wolfssl"], why: "wolfCrypt ECC keygen",
    code: `wc_ecc_make_key(&rng, 32, &eccKey);\n` },
  { id: "openssl-c-dh", ext: "c", expect: ["dh-openssl-c"], why: "OpenSSL C-API DH (param-gen form, single pattern)",
    code: `DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, NULL);\n` },
  { id: "rsa-pem", ext: "pem", expect: ["rsa-pem-header"], why: "PKCS#1 RSA private key block",
    code: `-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n` },
  { id: "ec-pem", ext: "pem", expect: ["ecc-pem-header"], why: "EC private key block",
    code: `-----BEGIN EC PRIVATE KEY-----\nMIIabc\n-----END EC PRIVATE KEY-----\n` },
  { id: "pkcs8-pem", ext: "pem", expect: ["pkcs8-pem-private-key"], why: "PKCS#8 key (algorithm unspecified)",
    code: `-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----\n` },
  { id: "webcrypto-rsa", ext: "ts", expect: ["rsa-webcrypto"], why: "Web Crypto RSA-OAEP as a tight identifier string",
    code: `const algo = { name: "RSA-OAEP", hash: "SHA-256" };\n` },
  { id: "ssh-rsa-quoted", ext: "yaml", expect: ["ssh-rsa-key"], why: "SSH RSA key as a quoted multi-word config value (v0.3.2 fix)",
    code: `admin_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDx root@bastion"\n` },
  { id: "ssh-ecdsa-quoted", ext: "yaml", expect: ["ssh-ecdsa-key"], why: "SSH ECDSA key as a quoted config value",
    code: `node_key: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAy deploy@host"\n` },
  { id: "cipher-list", ext: "yaml", expect: ["sym-aes128"], why: "OpenSSL cipher list (multi-token, no prose) must still count",
    code: `ciphers: "ECDHE-RSA-AES128-GCM-SHA256 DHE-RSA-AES128-GCM-SHA256 AES128-SHA"\n` },
  { id: "tls-rsa-cert", ext: "conf", expect: ["tls-rsa-cert"], why: "X.509 RSA signature algorithm",
    code: `signature_algorithm = sha256WithRSAEncryption\n` },
  { id: "dh-in-template", ext: "ts", expect: ["dh-keyexchange"], why: "real DH call inside a template interpolation (v0.3.2 fix)",
    code: "const q = `rotate ${createDiffieHellman(2048)} keys now`;\n" },
  { id: "same-line-prose-and-call", ext: "ts", expect: ["dh-keyexchange"], why: "a real call sharing a line with a prose mention (v0.3.2 fix)",
    code: `logger.info("rotating the diffie-hellman params now please"); createDiffieHellman(2048);\n` },

  // ─────────────────────────────── traps (must NOT count as exposure) ───────
  { id: "prose-migration", ext: "ts", expect: [], why: "prose naming primitives → possible mentions, not exposure",
    code: `const note = "we are migrating away from diffie-hellman and 3DES this quarter";\n` },
  { id: "comment-only", ext: "ts", expect: [], why: "crypto only in comments → masked",
    code: `// historical: used RSA, ECDSA, and mbedtls_rsa_gen_key here\nexport const X = 1;\n` },
  { id: "aes256-ok", ext: "ts", expect: [], why: "AES-256 is quantum-OK; identifiers ending in 256 must not fire",
    code: `const c = "aes-256-gcm";\nconst k = WINDOWS256;\n` },
  { id: "sha256-ok", ext: "ts", expect: [], why: "SHA-256 is not a legacy hash",
    code: `const h = createHash("sha256");\n` },
  { id: "jwt-enum-mention", ext: "ts", expect: [], why: "JWT alg enum is a low-confidence mention, not exposure",
    code: `export const SUPPORTED = ["RS256", "ES256"];\n` },
  { id: "java-jose-decl", ext: "java", expect: ["jwt-rsa-alg"],
    why: "a bare JOSE-alg constant declaration is a real RSA use (vs a string label like [\"RS256\"])",
    code: `public static final SignatureAlgorithm RS256 = get("RS256");\n` },
  { id: "py-docstring-dh", ext: "py", expect: [],
    why: "a crypto name inside a Python docstring is prose, not a use",
    code: `def f():\n    """\n    Standard SSH key exchange using Diffie-Hellman group14.\n    """\n    return 1\n` },
  { id: "py-docstring-sshrsa", ext: "py", expect: [],
    why: "ssh-rsa named only as a docstring example is a mention, though it is key material in a real key file",
    code: `def load(type_):\n    """\n    :param type_: key type indicator, for example ssh-rsa for RSA keys.\n    """\n    return type_\n` },
  { id: "ed25519-comment", ext: "py", expect: [], why: "ed25519 + rsa keygen only in a comment",
    code: `# migrate the ed25519 and rsa.generate_private_key path\nVALUE = 2\n` },
  { id: "doc-string-rsa", ext: "ts", expect: [], why: "prose doc string mentioning RSA/bits, no construction",
    code: `const help = "Generate an RSA key with at least 3072 bits for safety.";\n` },
  { id: "identifier-ecdsa", ext: "ts", expect: [], why: "ECDSA inside a camelCase identifier must not match (no word boundary, case-sensitive)",
    code: `let ecdsaSignature = computeSomething();\n` },
  { id: "baseline-file", ext: "json", expect: [], why: "a committed qbench/baseline-style file of opaque fingerprints must not self-trip",
    code: `{ "tool": "QuantumVault", "fingerprints": ["6ff5962fb4ff422d", "a1b2c3d4e5f60718"] }\n` },
  { id: "aes256-cipher-list", ext: "yaml", expect: [], why: "a modern cipher list (AES-256 only) is not exposure",
    code: `ciphers: "ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-AES256-GCM-SHA384"\n` },

  // ── v0.3.4: key-material recall fixes (were false negatives; now detected) ──
  { id: "openssh-private-key", ext: "pem", expect: ["openssh-pem-private-key"], why: "OpenSSH-format private key (default ssh-keygen output) — was missed",
    code: `-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAA\n-----END OPENSSH PRIVATE KEY-----\n` },
  { id: "encrypted-pkcs8", ext: "pem", expect: ["pkcs8-encrypted-pem"], why: "encrypted PKCS#8 key — was missed (ENCRYPTED keyword slipped past plain PKCS#8)",
    code: `-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG\n-----END ENCRYPTED PRIVATE KEY-----\n` },
  { id: "pgp-public", ext: "pem", expect: ["pgp-public-block"], why: "PGP public key block — was missed (only the private block was caught)",
    code: `-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQENBFexamplepublickeyblockdata\n=AbCd\n-----END PGP PUBLIC KEY BLOCK-----\n` },
  { id: "jwk-rsa", ext: "json", expect: ["jwk-asymmetric-key"], why: "JWK RSA key material — was missed (no kty pattern)",
    code: `{ "kty": "RSA", "use": "sig", "n": "0vx7agoebGcQ", "e": "AQAB", "kid": "k1" }\n` },

  // ── v0.3.4: PQC certs must NOT be flagged RSA (tls-rsa-cert greedy/path fix) ──
  { id: "pqc-cert-mldsa", ext: "yaml", expect: [], why: "a PQC ML-DSA signatureAlgorithm line must not be mislabeled RSA (greedy .*RSA fix)",
    code: `signatureAlgorithm: ML-DSA-65, fallbackName: RSA-PSS-disabled\n` },
  { id: "pqc-cert-path", ext: "conf", expect: [], why: "an ssl_certificate path carries no algorithm — must not assert RSA (path-arm dropped)",
    code: `ssl_certificate /etc/ssl/pqc/dilithium.pem;\n` },

  // ── v0.3.4: probe-confirmed correct behavior — regression guards ────────────
  { id: "guard-pqc-safe", ext: "py", expect: [], why: "PQC algorithms (SLH-DSA/Falcon/Kyber) are quantum-safe and must never be flagged",
    code: `pk = SLH_DSA_SHA2_128s.keygen()\nf = Falcon512.sign(m)\nk = Kyber768.encap()\n` },
  { id: "guard-prose-tripledes", ext: "ts", expect: [], why: "a 3-word prose string with stopwords is correctly a low mention (pairs with the gap-short-string FP)",
    code: `const err = report("TripleDES is not supported here");\n` },
  { id: "guard-forge-rsa", ext: "js", expect: ["rsa-keygen-openssl"], why: "node-forge RSA keygen is correctly caught (camelCase generateKeyPair path)",
    code: `const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });\n` },
  { id: "guard-enc-ec-pem", ext: "pem", expect: ["ecc-pem-header"], why: "encrypted EC key keeps its typed header; the AES-256-CBC DEK line is correctly not exposure",
    code: `-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,B2F8\nMIHexample\n-----END EC PRIVATE KEY-----\n` },

  // ── v0.3.5: label / message / identifier mentions no longer count as exposure
  //    (mention classifier = natural-language word in a >=2-word string;
  //     sym-des-3des gained a trailing word boundary)
  { id: "mention-label-3des", ext: "ts", expect: [], why: "a 2-word label string ('3DES weak') is a mention, not a use",
    code: `const label = "3DES weak";\n` },
  { id: "mention-toast-dh", ext: "ts", expect: [], why: "a UI/error string with no stopword ('Diffie-Hellman handshake failed') is a mention",
    code: `const toast = "Diffie-Hellman handshake failed";\n` },
  { id: "mention-banner-aes128", ext: "ts", expect: [], why: "a status string ('AES128 disabled') is a mention",
    code: `const banner = "AES128 disabled";\n` },
  { id: "mention-errmsg-dss", ext: "ts", expect: [], why: "a log/error string ('ssh-dss key rejected') is a mention",
    code: `const errmsg = "ssh-dss key rejected";\n` },
  { id: "identifier-class-3des", ext: "ts", expect: [], why: "a class name carrying a token (TripleDESLegacyAdapter) is not a cipher use (trailing-\\b fix)",
    code: `class TripleDESLegacyAdapter {}\n` },
  { id: "identifier-envvar-3des", ext: "ts", expect: [], why: "an env-var name (TRIPLEDES_FALLBACK_DISABLED) is not a cipher use (trailing-\\b fix)",
    code: `const v = process.env.TRIPLEDES_FALLBACK_DISABLED;\n` },

  // ── v0.3.6: recall expansion — real uses/formats that were silently missed ──
  { id: "go-ecdsa-keygen", ext: "go", expect: ["go-ecdsa"], why: "Go ECDSA key generation — was missed (only crypto/rsa was covered)",
    code: `k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)\n` },
  { id: "go-dsa-keygen", ext: "go", expect: ["go-dsa"], why: "Go DSA key generation (capital-G GenerateKey) — was missed (case-sensitive dsa-usage)",
    code: `dsa.GenerateKey(priv, rand.Reader)\n` },
  { id: "evp-pkey-keygen", ext: "c", expect: ["evp-pkey-keygen"], why: "OpenSSL 3.x generic EVP_PKEY_keygen entry point — was missed",
    code: `EVP_PKEY_keygen(ctx, &pkey);\n` },
  { id: "webcrypto-ecdsa", ext: "ts", expect: ["ecc-webcrypto"], why: "Web Crypto ECDSA generateKey call — was only flagged low via the bare curve name",
    code: `crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);\n` },
  { id: "x509-cert", ext: "pem", expect: ["x509-cert-body"], why: "a deployed X.509 certificate body (RSA/ECC public key + signature) — was missed",
    code: `-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBa\n-----END CERTIFICATE-----\n` },

  // ── v0.3.7: overlapping-pattern double-counts collapsed + PKCS#12 detected ──
  { id: "dh-single-count", ext: "c", expect: ["dh-openssl-c"], why: "DH_generate_key now fires only dh-openssl-c (removed from dh-keyexchange) — one finding, not two",
    code: `DH_generate_key(dh);\n` },
  { id: "java-keygen-single-count", ext: "java", expect: ["rsa-java-keypairgen"], why: "chained getInstance('RSA').generateKeyPair() now fires only rsa-java-keypairgen (java dropped from rsa-keygen-openssl)",
    code: `KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();\n` },
  { id: "pkcs12-decode", ext: "go", expect: ["pkcs12-keystore"], why: "a PKCS#12 keystore (.pfx/pkcs12.Decode) bundling a private key + cert — was missed",
    code: `pkcs12.Decode(data, "changeit")\n` },

  // ── v0.3.8: route/URL slugs and disable directives no longer count as exposure
  //    (path/URL classifier + disable-directive override of never-downgrade) ──
  { id: "route-slug-dh", ext: "ts", expect: [], why: "a REST route string ('/api/v2/diffie-hellman/rotate') names an endpoint — a path slug, not a DH use",
    code: `const route = "/api/v2/diffie-hellman/rotate";\n` },
  { id: "url-slug-dh", ext: "ts", expect: [], why: "a URL with a crypto path segment ('https://host/v2/diffie-hellman/rotate') is an endpoint, not a DH use (:// branch)",
    code: `const url = "https://api.example.com/v2/diffie-hellman/rotate";\n` },
  { id: "route-slug-single-segment", ext: "ts", expect: [], why: "a single-segment route ('/diffie-hellman') is still a route slug, not a DH use (leading-slash branch, any segment count)",
    code: `router.get("/diffie-hellman", rotateParams);\n` },
  { id: "path-keymaterial-stays", ext: "json", expect: ["ssh-rsa-key"], why: "key material named in a path ('/keys/ssh-rsa/import') is NOT downgraded — never-downgrade wins over the path rule",
    code: `{ "callback": "/keys/ssh-rsa/import/v2" }\n` },
  { id: "denylist-disabled", ext: "json", expect: [], why: "a config that DISABLES key types ('ssh-rsa': false) is remediation, not exposure (overrides never-downgrade)",
    code: `{ "ssh-rsa": false, "ecdsa-sha2-nistp256": false }\n` },
  { id: "yaml-disable-unquoted", ext: "yaml", expect: [], why: "an unquoted YAML disable directive (ssh-rsa: false) — a bare-token key, not in a string span — still downgrades",
    code: `ssh-rsa: false\n` },
  // recall guards: the disable/path rules must not over-downgrade real exposure
  { id: "guard-allowlist-enables", ext: "json", expect: ["ssh-rsa-key"], why: "allow-listing a weak key type (value position, not a disabled key) is real exposure and must still fire",
    code: `{ "allowedKeyTypes": ["ssh-rsa", "ed25519"] }\n` },
  { id: "guard-config-enabled-true", ext: "json", expect: ["ssh-rsa-key"], why: "an ENABLED weak key type ('ssh-rsa': true) is not a disable directive and must still fire",
    code: `{ "ssh-rsa": true }\n` },

  // ── v0.3.9: Windows path FP cleared + DH detected in config languages ──
  { id: "windows-path-dh", ext: "py", expect: [], why: "a Windows drive path naming a primitive ('C:\\\\certs\\\\diffie-hellman.pem') is a path reference, not a use (drive-letter branch)",
    code: `PARAMS_FILE = "C:\\\\certs\\\\diffie-hellman.pem"\n` },
  { id: "yaml-dh-config-value", ext: "yaml", expect: ["dh-keyexchange"], why: "a key-exchange config naming diffie-hellman is a real DH posture — now detected on config languages (was a recall miss)",
    code: `keyExchange: diffie-hellman\n` },
  { id: "json-dh-config-value", ext: "json", expect: ["dh-keyexchange"], why: "a quoted DH config value ('keyExchange': 'diffie-hellman') fires — single tight token, not a mention/disable/path",
    code: `{ "keyExchange": "diffie-hellman" }\n` },
  // recall guards for the broadened DH coverage: the classifier must still downgrade non-uses on config
  { id: "yaml-dh-disabled", ext: "yaml", expect: [], why: "a disabled DH directive (diffie-hellman: false) on config is remediation, not exposure",
    code: `diffie-hellman: false\n` },
  { id: "yaml-dh-comment", ext: "yaml", expect: [], why: "diffie-hellman only in a YAML '#' comment is masked — no finding even with config coverage",
    code: `# legacy diffie-hellman support was removed\nkeyExchange: ml-kem\n` },

  // ── v0.3.10: enum-constant references downgraded (zero-dep call-vs-reference) ──
  { id: "enum-ref-dsa-assign", ext: "ts", expect: [], why: "a bare enum read assigned to a variable (= SignatureAlgorithm.DSA) is a reference, not a signing use — downgraded to a possible mention",
    code: `const x = SignatureAlgorithm.DSA;\n` },
  // recall guards: the enum-ref rule must NOT swallow real DSA/DES uses
  { id: "guard-dsa-method-call-bare", ext: "ts", expect: [], why: "an isolated dsa.generate(...) on an unknown receiver is lexically identical to a DataSourceAdapter.generate() — a possible mention, not exposure, until the file shows real crypto context (ENG-01a file-scope corroboration)",
    code: `const k = dsa.generate(params);\n` },
  { id: "guard-dsa-method-call-corroborated", ext: "ts", expect: ["dsa-usage"], why: "the SAME dsa.generate(...) call in a file that imports crypto is corroborated — a real keygen, actionable",
    code: `import "crypto";\nconst k = dsa.generate(params);\n` },
  { id: "guard-dsa-enum-arg", ext: "java", expect: ["dsa-usage"], why: "passing the enum to a signer (signWith(SignatureAlgorithm.DSA, key)) is an argument-position use — not a bare read, still fires",
    code: `signer.signWith(SignatureAlgorithm.DSA, key);\n` },
  { id: "guard-dsa-fluent-sign", ext: "ts", expect: ["dsa-usage"], why: "a fluent signing call (SignatureAlgorithm.DSA.sign(...)) is a real use — the trailing '.' keeps it at base confidence (not a bare read)",
    code: `sig = SignatureAlgorithm.DSA.sign(payload, key);\n` },
  { id: "guard-des-fluent-encrypt", ext: "js", expect: ["sym-des-3des"], why: "a fluent DES encrypt (Cipher.DES.encrypt(...)) is a real use — trailing '.' keeps it actionable",
    code: `out = Cipher.DES.encrypt(plaintext);\n` },
  { id: "guard-enum-ref-compare-stays", ext: "ts", expect: ["dsa-usage"], why: "a comparison (== SignatureAlgorithm.DSA) is left at base confidence — it may guard a real use, too ambiguous to downgrade without data flow",
    code: `if (algo == SignatureAlgorithm.DSA) { sign(); }\n` },
  { id: "regex-quote-no-mask-leak", ext: "ts", expect: [], why: "a regex with quote chars (/[\"']/) must not leak the comment-masker's string state into the next line — the following comment names a primitive and must stay masked",
    code: `const s = raw.replace(/^["']+|["']+$/g, "");\n// legacy diffie-hellman support was removed\n` },

  // ── messy-app-code precision (v0.5.1): coincidental identifiers that RESEMBLE a
  //    crypto shape but mean something mundane, in a file with NO crypto anywhere.
  //    An ambiguous shape without file-level corroboration is a possible mention,
  //    not exposure (see hasCryptoContext / isAmbiguousMatch). Each case is its own
  //    file, so — as in a real codebase where crypto lives in its own module — the
  //    coincidence file carries no crypto signal. ──
  { id: "coincidence-dh-generate", ext: "js", expect: [], why: "dh is a DateHelper; dh.generate() yields a date, not a Diffie-Hellman key — no crypto in the file, a possible mention",
    code: `const dh = new DateHelper(tz);\nconst nextRun = dh.generate(schedule);\n` },
  { id: "coincidence-dsa-generate", ext: "ts", expect: [], why: "dsa is a DataSourceAdapter; .generate() runs a query — no crypto context, a possible mention not exposure",
    code: `const dsa = new DataSourceAdapter(pool);\nconst rows = dsa.generate(reportQuery);\n` },
  { id: "coincidence-new-dsa", ext: "ts", expect: [], why: "DSA is a 'Delivery Service Area' value object; new DSA(zone) constructs a shipping zone, not a keypair",
    code: `class DSA { constructor(public zone: string) {} }\nconst area = new DSA("us-west");\n` },
  { id: "coincidence-rsa-create", ext: "cs", expect: [], why: "RSA is a 'Regional Sales Aggregator' app class; RSA.Create(cfg) with no key size and no crypto context is not System.Security.Cryptography",
    code: `var agg = RSA.Create(regionConfig);\n` },
  { id: "coincidence-dsa-create", ext: "cs", expect: [], why: "DSA is an app class (Delivery Schedule Assignment); DSA.Create(cfg) with no key size / crypto context is coincidental",
    code: `var plan = DSA.Create(routeConfig);\n` },
  { id: "coincidence-des3-hop", ext: "js", expect: [], why: "des3 = 'destination hop 3', a routing waypoint — a bare des3 token with no crypto context is not Triple-DES",
    code: `const des3 = hops[2];\ndeliver(des3);\n` },
  { id: "coincidence-aes128-enum", ext: "ts", expect: [], why: "AES128 is a retired billing-plan enum member ('annual-enterprise-svc-128'), not the cipher, in a file with no crypto",
    code: `enum PlanCode { BASIC, AES128, PRO }\nconst p = PlanCode.AES128;\n` },
  { id: "coincidence-md5sum-label", ext: "js", expect: [], why: "md5sum is the label of a non-security dedupe key (plain string concat, no hashing) — a possible mention",
    code: `const md5sum = plan.areaCode + ':' + plan.slot;\nreturn md5sum;\n` },
  { id: "coincidence-pkcs12-carton", ext: "php", expect: [], why: "'pkcs12' = 'Packing & Carton Set, 12-unit' warehouse code — a bare string, not a keystore, no crypto in the file",
    code: `$batch = 'pkcs12';\nreturn shipCartons($batch);\n` },
  { id: "coincidence-p12-filename", ext: "rb", expect: [], why: "report.p12 is an accounting 'period 12' export filename — the .p12 is not a PKCS#12 keystore, no crypto context",
    code: `path = "exports/reconcile_report.p12"\nupload(path)\n` },
  { id: "coincidence-generatekeypair-shard", ext: "cs", expect: [], why: "orderBook.generateKeyPair(shardCount) allocates a (partition, replica) tuple; a generic generateKeyPair with no key size / algorithm / crypto context is not RSA keygen",
    code: `var tuple = orderBook.generateKeyPair(shardCount);\n` },
  { id: "coincidence-p256-sku", ext: "swift", expect: [], why: "'P256.Signing' is an e-signature product SKU string (the 'Premium 256' add-on), not CryptoKit, in a file with no crypto",
    code: `let sku = "P256.Signing"\ncatalog.add(sku)\n` },
  { id: "coincidence-es256-warehouse", ext: "cs", expect: [], why: "ES256 = 'east-storage-256' warehouse tier constant; a bare JOSE-alg code token only upgrades in a JWT/JOSE file, so with no crypto context it stays a low mention",
    code: `const string ES256 = "east-storage-256";\n` },
  { id: "coincidence-jwk-shipping", ext: "php", expect: [], why: "a JSON with \"kty\":\"EC\" but NO JWK companion field (crv/x/y/n/e/kid) is a shipping descriptor (kty='kind-type', EC='Economy Class'), not a JWK",
    code: `$d = '{"kty":"EC","service":"ground","insured":false}';\n` },
  { id: "coincidence-ssh-rsa-disable-arrow", ext: "php", expect: [], why: "'ssh-rsa' => false is a PHP-array disable directive; an explicitly turned-off algorithm is remediation, not a live posture (disable overrides never-downgrade)",
    code: `$transports = ['ssh-rsa' => false, 'ssh-ed25519' => true];\n` },

  // ── recall controls: the SAME shapes, corroborated, MUST still fire ──
  { id: "control-rsa-create-keysize", ext: "cs", expect: ["rsa-dotnet"], why: "RSA.Create(2048) has a key-size argument — a real keygen, actionable even without other file context",
    code: `var r = RSA.Create(2048);\n` },
  { id: "control-generatekeypair-rsa", ext: "js", expect: ["rsa-keygen-openssl"], why: "generateKeyPairSync('rsa', { modulusLength: 2048 }) names the algorithm and key size — a real RSA keygen, stays actionable",
    code: `const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });\n` },
  { id: "control-des-ede3-real", ext: "js", expect: ["sym-des-3des"], why: "the unambiguous 3DES cipher spec (des-ede3-cbc) is a real use — not gated by corroboration",
    code: `const c = createCipheriv("des-ede3-cbc", key, iv);\n` },
  { id: "control-p256-cryptokit-real", ext: "swift", expect: ["ecc-swift-cryptokit"], why: "P256.Signing.PrivateKey() alongside a real crypto token (PrivateKey / CryptoKit) is corroborated — a real CryptoKit use",
    code: `import CryptoKit\nlet key = P256.Signing.PrivateKey()\n` },

  // ── v0.5.1 residual gaps, closed in v0.5.2 ──
  { id: "ssh-rsa-name-in-prose", ext: "js", expect: [], why: "a key-TYPE name ssh-rsa in a natural-language log/label with no adjacent key bytes is a name reference, not a key — the never-downgrade rule yields for prose (bareKeyName + proseMention)",
    code: `logger.info("redacted an ssh-rsa entry from the audit output");\n` },
  { id: "guard-ssh-rsa-real-key-in-prose", ext: "js", expect: ["ssh-rsa-key"], why: "a real ssh-rsa key line embedded in a prose string still carries the base64 blob — bareKeyName is false, so never-downgrade protects it",
    code: `const m = "rotate your key ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDx1a2b3c4d5e now";\n` },
  { id: "unquoted-config-path-slug", ext: "yaml", expect: [], why: "an UNQUOTED yaml value that is a route/path slug (/api/v2/diffie-hellman/rotate) names an endpoint, not a key exchange — downgraded even though it is not a string span",
    code: `routes:\n  rotate: /api/v2/diffie-hellman/rotate\n` },
  { id: "guard-unquoted-config-real-dh", ext: "yaml", expect: ["dh-keyexchange"], why: "a bare algorithm value (keyExchange: diffie-hellman) is a real DH posture, NOT a path — it still fires",
    code: `security:\n  keyExchange: diffie-hellman\n` },

  // ── i18n / localization catalog values are UI text, not key material (v0.6.0;
  //    surfaced by the real-repo benchmark on gitea's locale_*.json placeholders,
  //    across non-English locales the Latin-only mention rule couldn't read). The
  //    filename (locale_… / a locale-ish path) is the signal. ──
  { id: "locale-gpg-placeholder", ext: "json", expect: [], why: "a PGP key-armor header inside an i18n placeholder string is UI hint text — a locale catalog never holds a real key (localeFile downgrade beats the pgp key-material never-downgrade)",
    code: `{ "settings.key_content_gpg_placeholder": "Begins with '-----BEGIN PGP PUBLIC KEY BLOCK-----'" }\n` },
  { id: "locale-ssh-placeholder-nonlatin", ext: "json", expect: [], why: "a key-type placeholder listing in a NON-English locale (Greek prose the Latin-only mention rule can't recognize) — the locale-file signal downgrades it regardless of language",
    code: `{ "settings.key_content_ssh_placeholder": "Ξεκινάει με 'ssh-rsa', 'ecdsa-sha2-nistp256'" }\n` },
  { id: "guard-pgp-real-key-nonlocale", ext: "json", expect: ["pgp-public-block"], why: "a real PGP public-key block in a NON-locale JSON file still fires — the downgrade is scoped to localization catalogs, not all JSON",
    code: `{ "pubkey": "-----BEGIN PGP PUBLIC KEY BLOCK-----\\nmQINBGAbCdEFEEADx1a2b3c4d5e6f7g8h9i0jQ==\\n-----END PGP PUBLIC KEY BLOCK-----" }\n` },

  // ── Python type-annotation references are not uses (v0.6.1; from the pyca/
  //    cryptography benchmark). A crypto class named in a return annotation or a
  //    typing subscript is a type, not an operation. Scoped to Python. ──
  { id: "type-ref-return-annotation", ext: "py", expect: [], why: "a crypto type in a return annotation (-> DSAPrivateKey:) on an abstract/interface method names the type but performs no operation",
    code: `class DSAParameters:\n    def generate_private_key(self) -> DSAPrivateKey:\n        ...\n` },
  { id: "type-ref-union-member", ext: "py", expect: [], why: "a crypto type as a member of a typing subscript (Union[..., DSAPrivateKey]) is a type reference — the enclosing keyword 'Union', not the comma, proves it",
    code: `PKCS12Types = Union[\n    rsa.RSAPrivateKey,\n    dsa.DSAPrivateKey,\n]\n` },
  { id: "guard-type-instantiation-fires", ext: "py", expect: ["dsa-usage"], why: "DSAPrivateKey followed by ( is an instantiation, not a type reference — it still fires (the type-ref rule excludes anything followed by '(')",
    code: `import cryptography\nk = DSAPrivateKey(params)\n` },
  { id: "ini-semicolon-comment", ext: "ini", expect: [], why: "a leading ';' in an INI/config file is a comment — an 'openssl pkcs12' example there is documentation, not config (config lang now masks leading ';')",
    code: `;; example: openssl pkcs12 -in cert.pfx -out cert.pem -nokeys\nport = 8080\n` },

  // ── an empty PEM block is a placeholder, not key material (v0.6.1; from the
  //    smallstep/certificates benchmark — used as negative test inputs). ──
  { id: "empty-pem-placeholder", ext: "pem", expect: [], why: "-----BEGIN CERTIFICATE----- immediately followed by -----END----- with no base64 body is a negative/error test placeholder, not a cert — downgraded despite the key-material never-downgrade rule",
    code: `-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n` },
  { id: "guard-real-pem-cert", ext: "pem", expect: ["x509-cert-body"], why: "a PEM block WITH a base64 body is real certificate material and still fires — the empty-block downgrade requires the absence of any base64 body",
    code: `-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKZ7D5Yb0zzKMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv\nY2FsaG9zdDAeFw0yMDA1MDEwMDAwMDBaFw0zMDA1MDEwMDAwMDBaMBQ=\n-----END CERTIFICATE-----\n` },

  // ── ENG-02 (v0.7.0): X.509 certificate parsing — a block whose DER parses
  //    yields ONE enriched x509-certificate asset that REPLACES the generic
  //    x509-cert-body header finding (the v0.3.7 one-artifact-one-asset rule).
  //    The truncated-body cases above (x509-cert / guard-real-pem-cert) prove a
  //    FAILED parse keeps the generic finding — surfaced, never silent. ──
  { id: "x509-parsed-cert-dedupe", ext: "pem", expect: ["x509-certificate"], why: "a fully parseable certificate becomes one enriched cert asset; the generic x509-cert-body finding on the same header line is suppressed — one certificate, one asset",
    code: `-----BEGIN CERTIFICATE-----\nMIIBjjCCATWgAwIBAgIUJLfJ4xSveLlhVfIfz4CZLeFe2fcwCgYIKoZIzj0EAwIw\nHTEbMBkGA1UEAwwSZWNkc2EudW5pcXVlcy50ZXN0MB4XDTI2MDcwNDAxNDczMloX\nDTM2MDcwMTAxNDczMlowHTEbMBkGA1UEAwwSZWNkc2EudW5pcXVlcy50ZXN0MFkw\nEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEx9GL51CuPkB6Yb5D6ax0RnvqVOCLG450\nzexi9thcb5S9rDFB4SaPgHY2m16jbLOk6QWC8SkyFuMUlsu1PP+W8qNTMFEwHQYD\nVR0OBBYEFEFhv2WVt07ZuFkzouaLD4YdZa1AMB8GA1UdIwQYMBaAFEFhv2WVt07Z\nuFkzouaLD4YdZa1AMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIg\nJrxtlXpRDDGIFCLqCxckqKtrIdVZ4P/AJJupfPkmZ2sCIBgvz0ZBk3SZu0e8RNix\nkR+GA14k9FFCdiC3TvQYw65b\n-----END CERTIFICATE-----\n` },

  // ── ENG-02 (v0.7.0): TLS/SSH configuration posture. Each directive pattern
  //    fires only on a line that ENABLES legacy crypto; the guards prove the
  //    modern/disabled/prose forms stay clean. ──
  { id: "nginx-legacy-protocols", ext: "conf", expect: ["tls-legacy-protocol-nginx"], why: "an nginx ssl_protocols line enabling TLSv1/TLSv1.1 is a live legacy-TLS posture",
    code: `ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n` },
  { id: "nginx-weak-ciphers", ext: "conf", expect: ["tls-weak-cipher-nginx"], why: "ssl_ciphers enabling RC4/3DES suites (incl. mid-name tokens like ECDHE-RSA-RC4-SHA) is weak-cipher exposure",
    code: `ssl_ciphers ECDHE-RSA-RC4-SHA:DES-CBC3-SHA:HIGH;\n` },
  { id: "nginx-static-rsa-kx", ext: "conf", expect: ["tls-weak-cipher-nginx"], why: "a TLS_RSA_ suite is static-RSA key exchange — no forward secrecy, prime harvest-now-decrypt-later exposure",
    code: `ssl_ciphers TLS_RSA_WITH_AES_128_CBC_SHA;\n` },
  { id: "apache-legacy-protocol", ext: "conf", expect: ["tls-legacy-protocol-apache"], why: "Apache SSLProtocol with a bare/+ legacy token ENABLES it",
    code: `SSLProtocol +SSLv3 +TLSv1\n` },
  { id: "apache-weak-ciphersuite", ext: "conf", expect: ["tls-weak-cipher-apache"], why: "Apache SSLCipherSuite enabling an RC4 suite",
    code: `SSLCipherSuite HIGH:RC4-SHA\n` },
  { id: "haproxy-legacy-bind", ext: "cfg", expect: ["tls-legacy-haproxy"], why: "HAProxy force-tlsv10 pins the bind to TLS 1.0",
    code: `ssl-default-bind-options force-tlsv10\n` },
  { id: "haproxy-legacy-min-ver", ext: "cfg", expect: ["tls-legacy-haproxy"], why: "HAProxy ssl-min-ver set to a LEGACY floor (TLSv1.0) admits legacy TLS — the ssl-min-ver arm, distinct from force-*",
    code: `ssl-default-bind-options ssl-min-ver TLSv1.0\n` },
  { id: "haproxy-weak-ciphers", ext: "cfg", expect: ["tls-legacy-haproxy"], why: "HAProxy ssl-default-bind-ciphers enabling an RC4 suite — the ciphers arm, distinct from the options arms",
    code: `ssl-default-bind-ciphers ECDHE-RSA-RC4-SHA:HIGH\n` },
  { id: "haproxy-static-rsa-kx", ext: "cfg", expect: ["tls-legacy-haproxy"], why: "an ENABLED TLS_RSA_ suite in HAProxy bind ciphers is static-RSA key exchange exposure",
    code: `ssl-default-bind-ciphers TLS_RSA_WITH_AES_128_GCM_SHA256\n` },
  { id: "apache-static-rsa-kx", ext: "conf", expect: ["tls-weak-cipher-apache"], why: "an ENABLED TLS_RSA_ suite in Apache SSLCipherSuite is static-RSA key exchange exposure",
    code: `SSLCipherSuite HIGH:TLS_RSA_WITH_AES_128_CBC_SHA\n` },
  { id: "sshd-classical-kex", ext: "conf", expect: ["ssh-classical-kex"], why: "a KexAlgorithms list with ONLY classical kex (ecdh-*/diffie-hellman-*) and no PQC hybrid is quantum-vulnerable key exchange — and fires ONCE (dh-keyexchange yields the line to ssh-classical-kex, no double count)",
    code: `KexAlgorithms ecdh-sha2-nistp256,diffie-hellman-group14-sha256\n` },
  { id: "sshd-long-kex-dedupe", ext: "conf", expect: ["ssh-classical-kex"], why: "the one-line-one-asset dedupe must hold even when the first diffie-hellman token sits >500 chars into a legal (<1000 char) KexAlgorithms line — the dh-keyexchange lookbehind now reaches the scanner's full 1000-char line gate",
    code: `KexAlgorithms ${"curve25519-sha256@libssh.org,".repeat(20)}diffie-hellman-group14-sha256\n` },
  // recall/precision guards for the posture patterns
  { id: "guard-nginx-modern-protocols", ext: "conf", expect: [], why: "a modern-only ssl_protocols line (TLSv1.2/1.3) must NOT fire — TLSv1 is not a prefix-match of TLSv1.2",
    code: `ssl_protocols TLSv1.2 TLSv1.3;\n` },
  { id: "guard-nginx-cipher-exclusions", ext: "conf", expect: [], why: "OpenSSL kill syntax (!RC4, !3DES, a killed compound name, a killed/removed TLS_RSA_ suite) EXCLUDES the suite — remediation, not exposure",
    code: `ssl_ciphers HIGH:!aNULL:!RC4:!3DES:!EDH-RSA-DES-CBC3-SHA:!TLS_RSA_WITH_AES_128_CBC_SHA:-TLS_RSA_WITH_AES_256_CBC_SHA;\n` },
  { id: "guard-apache-cipher-exclusions", ext: "conf", expect: [], why: "Apache SSLCipherSuite using OpenSSL kill syntax (incl. a killed TLS_RSA_ suite) is hardening, not exposure",
    code: `SSLCipherSuite HIGH:!aNULL:!RC4:!3DES:!TLS_RSA_WITH_AES_128_CBC_SHA\n` },
  { id: "guard-haproxy-cipher-exclusions", ext: "cfg", expect: [], why: "HAProxy bind ciphers using OpenSSL kill syntax (incl. a killed TLS_RSA_ suite) is hardening, not exposure",
    code: `ssl-default-bind-ciphers HIGH:!RC4:!3DES:!TLS_RSA_WITH_AES_128_CBC_SHA\n` },
  { id: "guard-apache-disable-legacy", ext: "conf", expect: [], why: "the canonical hardening line 'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1' DISABLES legacy protocols and must not fire",
    code: `SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n` },
  { id: "guard-haproxy-modern", ext: "cfg", expect: [], why: "no-sslv3/no-tlsv10 disable, and ssl-min-ver TLSv1.2 is a modern floor — not exposure",
    code: `ssl-default-bind-options no-sslv3 no-tlsv10 ssl-min-ver TLSv1.2\n` },
  { id: "guard-sshd-pqc-hybrid", ext: "conf", expect: [], why: "a KexAlgorithms list that INCLUDES a PQC hybrid (sntrup761x25519/mlkem768x25519) is the fixed posture and must not fire",
    code: `KexAlgorithms sntrup761x25519-sha512,mlkem768x25519-sha256,ecdh-sha2-nistp256\n` },
  { id: "guard-sshd-kex-removal", ext: "conf", expect: [], why: "'KexAlgorithms -…' REMOVES algorithms from the default set — remediation, not an enablement",
    code: `KexAlgorithms -diffie-hellman-group1-sha1\n` },
  { id: "guard-nginx-commented-legacy", ext: "conf", expect: [], why: "a commented-out legacy ssl_protocols line is masked; the live line is modern-only",
    code: `# ssl_protocols TLSv1 TLSv1.1;\nssl_protocols TLSv1.2 TLSv1.3;\n` },
  { id: "guard-tls-prose-mention", ext: "yaml", expect: [], why: "a prose string RECOUNTING an ssl_protocols change is a mention, not a live directive",
    code: `note: "we removed the ssl_protocols TLSv1 line and disabled SSLv3 everywhere"\n` },
];

/**
 * KNOWN_GAPS — cases the engine does NOT yet handle correctly. These are the
 * precision worklist (mostly ENG-01b / option-3 targets), tracked but NOT gated,
 * so the QBENCH gate stays an honest 1.0. `expect` is the CORRECT behavior; the
 * informational qbench-gaps check reports which are still open and flags any that
 * have been resolved (promote those into QBENCH). Add a gap here whenever the
 * benchmark or an adversarial probe surfaces a real precision miss.
 */
export const KNOWN_GAPS: QCase[] = [
  // History (resolved + promoted into the gated QBENCH corpus):
  //  - v0.3.5: short label strings, no-stopword messages, identifier substrings
  //  - v0.3.7: overlapping-pattern double-counts, PKCS#12, no-extension SSH gate
  //  - v0.3.8: URL/route path slugs and disable-directive config keys
  //  - v0.3.9: Windows drive paths + DH-on-config recall
  //  - v0.3.10: bare enum-constant references (the call-vs-reference stand-in)
  //  - v0.5.1: coincidental ambiguous shapes in NON-crypto files — file-scope
  //    corroboration (coincidence-*/control-* cases)
  //  - v0.5.2: ssh key-type NAME in prose (bareKeyName + proseMention) and unquoted
  //    config path/route slugs (ssh-rsa-name-in-prose/unquoted-config-path-slug)
  //  - v0.6.0: i18n localization-catalog values (isLocaleResourceFile)
  //  - v0.6.1: Python type-annotation references — `-> X` and Union[…]/type[…]
  //    subscripts (isTypeReferenceAt) — and INI leading-`;` comments (type-ref-*/
  //    ini-semicolon-comment cases)
  //
  // ── OPEN — the residual the zero-dependency lexical engine cannot close without
  //    call-vs-object DATA FLOW (ENG-01b / tree-sitter AST). Documented and measured,
  //    NOT gated, so the 1.0 gate stays honest. ──
  { id: "gap-ambiguous-in-crypto-file", ext: "js", gapKind: "fp", expect: [],
    why: "an ambiguous shape (dh.generate where dh is a DateHelper) that shares a FILE with real crypto is kept actionable by file-scope corroboration — telling the coincidental receiver from a real DiffieHellman needs data flow (ENG-01b), not lexical file context. Rare in real code (a DateHelper is not named `dh` in a file that also holds a DiffieHellman), so held as the marker for ENG-01b rather than chased lexically.",
    code: `const dh = new DateHelper(tz);\nconst when = dh.generate(schedule);\nconst real = createDiffieHellman(2048);\n` },

  // ── OPEN — surfaced by the reproducible public-repo benchmark (bench/). Each needs
  //    type/data-flow awareness a lexical pass can't cleanly give. ──
  { id: "gap-type-ref-isinstance-tuple", ext: "py", gapKind: "fp", expect: [],
    why: "a crypto type inside an isinstance() / accepted-types TUPLE (isinstance(k, (rsa.RSAPrivateKey, dsa.DSAPrivateKey))) is a type reference, not a use — but a `(…)` tuple is lexically a call arg-list, so the type-ref rule (which handles `-> X` and Union[…] subscripts) leaves it. Needs isinstance/tuple-context awareness. pyca residual.",
    code: `if isinstance(k, (rsa.RSAPrivateKey, dsa.DSAPrivateKey)):\n    pass\n` },
  { id: "gap-prose-in-interpolated-template", ext: "js", gapKind: "fp", expect: [],
    why: "a crypto name in a NATURAL-LANGUAGE error message that is a template literal WITH an interpolation (throw new Error(`… RSA-PSS … ${alg}`)) is not downgraded — the template-${} case is deliberately left at base confidence because a real call can live in the interpolation. The jsonwebtoken FP class; needs interpolation-vs-prose parsing.",
    code: "throw new Error(`Invalid RSA-PSS parameters for alg ${alg}`);\n" },
  { id: "gap-denylist-removal-call", ext: "c", gapKind: "fp", expect: [],
    why: "an algorithm name passed to a REMOVAL/denylist function (match_filter_denylist(list, \"diffie-hellman-group1-sha1\")) is a disable in disguise — the line removes the algorithm for old-client compat, it does not use it. The openssh FP class; needs knowing which callees are denylist sinks (data flow).",
    code: `match_filter_denylist(list, "diffie-hellman-group1-sha1");\n` },
  { id: "gap-apache-sslprotocol-all", ext: "conf", gapKind: "fn", expect: ["tls-legacy-protocol-apache"],
    why: "a bare `SSLProtocol all` enables every protocol the SERVER BUILD supports — on old Apache/OpenSSL builds that includes SSLv3/TLS 1.0, on modern builds it does not. Whether it is exposure depends on the deployed binary's version, which a source scan cannot see; flagging every `all` would FP on every modern deployment. Held as a documented scope boundary of the lexical posture check (ENG-02).",
    code: `SSLProtocol all\n` },
  // Smaller benchmark FP classes, context-dependent and not reproduced as isolated
  // cases (tracked in bench/REPORT.md): a Rust `pub mod pkcs12;` / `use …::pkcs12`
  // module declaration (names crypto, no operation); a `name="DES"` display-label
  // kwarg; a crypto token as a substring of a test-vector FILE PATH; and a function
  // name echoed in a log string beside the real call (openssh skdebug double-count).
];
