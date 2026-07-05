import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { scoreAsset, scoreAssets, getRiskWeights, DEFAULT_WEIGHTS } from "../risk/scorer.js";
import { extractKeyBits, patternCount, PATTERNS, confidenceFor } from "../discovery/patterns.js";
import { normalizeRepo } from "../discovery/repo.js";
import { scanDirectory } from "../discovery/scanner.js";
import { assetsToCsv } from "../discovery/csv.js";
import { assetsToCbom, validateCbom } from "../discovery/cbom.js";
import { quantumExposure } from "../discovery/cryptoRef.js";
import { assetsToSarif } from "../discovery/sarif.js";
import { openApiDocument } from "../openapi.js";
import { RateLimiter, rateLimit } from "../auth/rateLimit.js";
import type { Request, Response } from "express";
import type { CryptoAsset, CryptoFamily } from "../types.js";

/** Build a minimal valid CryptoAsset for scoring tests. */
function asset(partial: Partial<CryptoAsset> & { family: CryptoFamily }): CryptoAsset {
  return {
    id: "a1",
    scanId: "s1",
    file: "src/app.ts",
    line: 1,
    algorithm: "X",
    keyBits: null,
    language: "typescript",
    snippet: "",
    patternId: "p",
    quantumVulnerable: true,
    confidence: "high",
    pqcReplacement: "ML-KEM (Kyber)",
    status: "open",
    ...partial,
  };
}

// ---------------------------------------------------------------- risk scorer
test("risk: RSA PEM key on a sensitive auth path scores critical", () => {
  const r = scoreAsset(
    asset({
      family: "RSA",
      file: "services/auth/payment/secret.pem",
      patternId: "rsa-pem-header",
      algorithm: "RSA",
    }),
  );
  assert.equal(r.priority, "critical");
  assert.ok(r.score >= 80, `expected >=80, got ${r.score}`);
  assert.match(r.recommendation, /Immediately migrate/);
});

test("risk: legacy hash (MD5/SHA-1) scores well below a broken RSA key", () => {
  const hash = scoreAsset(asset({ family: "HashLegacy", patternId: "hash-md5-sha1", file: "util/hash.ts" }));
  const rsa = scoreAsset(asset({ family: "RSA", patternId: "rsa-pem-header", file: "auth/key.pem" }));
  assert.ok(hash.score < rsa.score, `hash ${hash.score} should be < rsa ${rsa.score}`);
});

test("risk: all five factors stay within 0..100 and weights yield a bounded score", () => {
  for (const family of ["RSA", "ECC", "DSA", "DH", "SymmetricLegacy", "HashLegacy"] as CryptoFamily[]) {
    const r = scoreAsset(asset({ family }));
    for (const [k, v] of Object.entries(r.factors)) {
      assert.ok(v >= 0 && v <= 100, `${family}.${k} out of range: ${v}`);
    }
    assert.ok(r.score >= 0 && r.score <= 100);
    assert.ok(r.migrationEffortDays > 0);
  }
});

test("risk: deployment context de-prioritizes test/vendor findings vs production", () => {
  const mk = (file: string) => scoreAsset(asset({ family: "ECC", patternId: "ecc-pem-header", algorithm: "ECDSA", file }));
  const prod = mk("src/services/auth/signing-ec.key");
  const test = mk("tests/fixtures/signing-ec.key");
  const vendor = mk("node_modules/jose/signing-ec.key");

  // Same key, different context — production must outrank test and vendor.
  assert.ok(prod.score > test.score, `prod ${prod.score} should beat test ${test.score}`);
  assert.ok(test.score > vendor.score, `test ${test.score} should beat vendor ${vendor.score}`);
  assert.equal(prod.contextMultiplier, 1);
  assert.equal(test.deploymentContext, "test/example code");
  assert.equal(vendor.deploymentContext, "vendored dependency");
  // The "wall of alerts" fix: a test fixture must not be high/critical.
  assert.ok(["low", "medium"].includes(test.priority), `test fixture should not be ${test.priority}`);
  assert.match(test.recommendation, /de-prioritized/);
  // score must stay the weighted sum of the (discounted) factors it reports.
  const W = getRiskWeights();
  const expected =
    test.factors.dataSensitivity * W.dataSensitivity +
    test.factors.retentionExposure * W.retentionExposure +
    test.factors.hndlExposure * W.hndlExposure +
    test.factors.complianceImpact * W.complianceImpact +
    test.factors.businessImpact * W.businessImpact;
  assert.ok(Math.abs(test.score - Math.round(expected)) <= 1, "score should equal weighted sum of reported factors");
});

test("risk: Shor-broken asymmetric crypto gets a higher HNDL factor than symmetric", () => {
  const ecc = scoreAsset(asset({ family: "ECC", file: "transport/vpn/tls.ts" }));
  const sym = scoreAsset(asset({ family: "SymmetricLegacy", file: "transport/vpn/tls.ts" }));
  assert.ok(ecc.factors.hndlExposure > sym.factors.hndlExposure);
});

// ── ⚑4: AES-128 is Grover-weakened — a distinct, honestly-lower tier ─────────
test("exposure taxonomy: shor-broken vs grover-weakened vs classically-weak vs none", () => {
  assert.equal(quantumExposure(asset({ family: "RSA", algorithm: "RSA" })), "shor-broken");
  assert.equal(quantumExposure(asset({ family: "Asymmetric", algorithm: "Private key (PKCS#8)" })), "shor-broken");
  assert.equal(quantumExposure(asset({ family: "SymmetricLegacy", algorithm: "AES-128", patternId: "sym-aes128" })), "grover-weakened");
  assert.equal(quantumExposure(asset({ family: "SymmetricLegacy", algorithm: "DES/3DES", patternId: "sym-des-3des" })), "classically-weak");
  assert.equal(
    quantumExposure(asset({ family: "SymmetricLegacy", algorithm: "Weak TLS cipher suite (RC4/DES/3DES or static-RSA key exchange)", patternId: "tls-weak-cipher-nginx" })),
    "classically-weak",
  );
  assert.equal(quantumExposure(asset({ family: "HashLegacy", algorithm: "MD5/SHA-1" })), "classically-weak");
  assert.equal(quantumExposure(asset({ family: "PQC", algorithm: "ML-DSA-65", quantumVulnerable: false })), "none");
});

test("risk (⚑4): AES-128 is weighted below Shor-broken AND below classically-weak ciphers", () => {
  const mk = (algorithm: string, patternId: string) =>
    scoreAsset(asset({ family: "SymmetricLegacy", algorithm, patternId, file: "transport/vpn/tls.ts" }));
  const aes = mk("AES-128", "sym-aes128");
  const des = mk("DES/3DES", "sym-des-3des");
  const rsa = scoreAsset(asset({ family: "RSA", algorithm: "RSA", patternId: "rsa-keygen-openssl", file: "transport/vpn/tls.ts" }));
  // No practical HNDL path against AES-128 — lower than 3DES (classically
  // harvestable) which is lower than Shor-broken key material.
  assert.ok(aes.factors.hndlExposure < des.factors.hndlExposure, `aes hndl ${aes.factors.hndlExposure} !< des ${des.factors.hndlExposure}`);
  assert.ok(des.factors.hndlExposure < rsa.factors.hndlExposure);
  assert.ok(aes.score < rsa.score, `aes ${aes.score} should be < rsa ${rsa.score}`);
  // Score stays the weighted sum of the reported factors — no hidden discount.
  const W = getRiskWeights();
  const expected =
    aes.factors.dataSensitivity * W.dataSensitivity +
    aes.factors.retentionExposure * W.retentionExposure +
    aes.factors.hndlExposure * W.hndlExposure +
    aes.factors.complianceImpact * W.complianceImpact +
    aes.factors.businessImpact * W.businessImpact;
  assert.ok(Math.abs(aes.score - Math.round(expected)) <= 1, "score must equal weighted sum of reported factors");
});

test("risk (⚑4): AES-128 never reaches high/critical, even on the most sensitive path", () => {
  // Worst-case path signals: every sensitivity hint the model knows about.
  const worst = scoreAsset(
    asset({ family: "SymmetricLegacy", algorithm: "AES-128", patternId: "sym-aes128",
      file: "src/auth/payment/billing/key-secret-token.ts" }),
  );
  assert.ok(["low", "medium"].includes(worst.priority), `grover-weakened must not be ${worst.priority}`);
  // …and it stays actionable: real effort, real recommendation, never zeroed out.
  assert.ok(worst.score > 0);
  assert.ok(worst.migrationEffortDays > 0);
});

test("risk (⚑4): AES-128 recommendation says normal upgrade cycle, not crypto emergency", () => {
  const aes = scoreAsset(asset({ family: "SymmetricLegacy", algorithm: "AES-128", patternId: "sym-aes128", pqcReplacement: "AES-256-GCM" }));
  assert.match(aes.recommendation, /normal upgrade cycle/);
  assert.match(aes.recommendation, /not a crypto emergency/);
  assert.doesNotMatch(aes.recommendation, /Immediately migrate/);
  // 3DES keeps the standard urgency language — it is weak for classical reasons.
  const des = scoreAsset(asset({ family: "SymmetricLegacy", algorithm: "DES/3DES", patternId: "sym-des-3des" }));
  assert.doesNotMatch(des.recommendation, /not a crypto emergency/);
});

test("risk: scoreAssets mutates the batch in place and attaches risk", () => {
  const batch = [asset({ family: "RSA" }), asset({ family: "DH" })];
  const out = scoreAssets(batch);
  assert.equal(out, batch);
  assert.ok(batch.every((a) => a.risk && typeof a.risk.score === "number"));
});

test("risk weights: defaults apply when QV_RISK_WEIGHTS is unset", () => {
  delete process.env.QV_RISK_WEIGHTS;
  assert.deepEqual(getRiskWeights(), DEFAULT_WEIGHTS);
});

test("risk weights: custom weights are merged, normalized to 1.0, and shift scores", () => {
  const prev = process.env.QV_RISK_WEIGHTS;
  try {
    // Heavily weight HNDL exposure; a partner-path key-exchange asset should score higher.
    const a = () => asset({ family: "DH", file: "transport/partner/vpn.ts", patternId: "dh-keyexchange" });
    const baseScore = scoreAsset(a()).score;

    process.env.QV_RISK_WEIGHTS = JSON.stringify({ hndlExposure: 5 });
    const w = getRiskWeights();
    const sum = Object.values(w).reduce((x, y) => x + y, 0);
    assert.ok(Math.abs(sum - 1) < 1e-9, `weights must normalize to 1.0, got ${sum}`);
    assert.ok(w.hndlExposure > DEFAULT_WEIGHTS.hndlExposure, "hndl weight should dominate");

    const tunedScore = scoreAsset(a()).score;
    assert.ok(tunedScore > baseScore, `tuned ${tunedScore} should exceed base ${baseScore} for a high-HNDL asset`);
  } finally {
    if (prev === undefined) delete process.env.QV_RISK_WEIGHTS;
    else process.env.QV_RISK_WEIGHTS = prev;
  }
});

test("risk weights: invalid JSON falls back to defaults", () => {
  const prev = process.env.QV_RISK_WEIGHTS;
  try {
    process.env.QV_RISK_WEIGHTS = "{not valid";
    assert.deepEqual(getRiskWeights(), DEFAULT_WEIGHTS);
  } finally {
    if (prev === undefined) delete process.env.QV_RISK_WEIGHTS;
    else process.env.QV_RISK_WEIGHTS = prev;
  }
});

// ------------------------------------------------------------- pattern db
test("patterns: patternCount matches the database length and health endpoint (59)", () => {
  assert.equal(patternCount(), PATTERNS.length);
  assert.equal(patternCount(), 59);
});

test("scanner: well-known SSH key files with no extension are scanned (authorized_keys)", () => {
  const dir = mkdtempSync(join(tmpdir(), "qv-sshfile-"));
  try {
    // No extension — would be skipped by languageFor without the filename allowlist.
    writeFileSync(join(dir, "authorized_keys"),
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgExampleRsaKeyData bob@host\n");
    const assets = scanDirectory(dir, "sshfile").assets;
    assert.ok(
      assets.some((a) => a.file === "authorized_keys" && a.patternId === "ssh-rsa-key"),
      "an ssh-rsa key in authorized_keys must be detected",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("patterns: every pattern has a non-empty PQC replacement and a unique id", () => {
  const ids = new Set<string>();
  for (const p of PATTERNS) {
    assert.ok(p.pqcReplacement.length > 0, `${p.id} missing pqcReplacement`);
    assert.ok(!ids.has(p.id), `duplicate pattern id: ${p.id}`);
    ids.add(p.id);
  }
});

test("patterns: extended detectors fire and resist common false positives", () => {
  const dir = mkdtempSync(join(tmpdir(), "qv-ext-"));
  try {
    writeFileSync(join(dir, "jwt.ts"), 'const opts = { algorithm: "RS256" };\nconst v = { alg: "ES256" };\n');
    writeFileSync(join(dir, "key.pem"), "-----BEGIN EC PRIVATE KEY-----\nabc\n-----END EC PRIVATE KEY-----\n");
    writeFileSync(join(dir, "main.go"), 'import "crypto/rsa"\n');
    writeFileSync(join(dir, "infra.tf"), 'key = "ecdsa-sha2-nistp256 AAAA"\n');
    // False-positive bait: AES-256 is quantum-OK and must NOT trigger the ES256
    // matcher; neither should arbitrary identifiers ending in 256.
    writeFileSync(join(dir, "clean.ts"), 'const c = "aes-256-gcm";\nconst k = "AES256KEY";\nconst n = WINDOWS256;\n');

    const { assets } = scanDirectory(dir, "ext-test");
    const ids = new Set(assets.map((a) => a.patternId));
    assert.ok(ids.has("jwt-rsa-alg"), "RS256 detected");
    assert.ok(ids.has("jwt-ecdsa-alg"), "ES256 detected");
    assert.ok(ids.has("ecc-pem-header"), "EC private-key PEM detected");
    assert.ok(ids.has("go-crypto-rsa"), "crypto/rsa import detected");
    assert.ok(ids.has("ssh-ecdsa-key"), "ssh ecdsa key type detected");

    const cleanHits = assets.filter((a) => a.file === "clean.ts").map((a) => a.patternId);
    assert.equal(cleanHits.length, 0, `clean.ts should yield no findings, got: ${cleanHits.join(", ")}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("patterns: runtime crypto-API detectors fire across .NET/Python/Node/Swift", () => {
  const dir = mkdtempSync(join(tmpdir(), "qv-rt-"));
  try {
    writeFileSync(join(dir, "Crypto.cs"), "var r = RSA.Create(2048);\nvar e = ECDsa.Create();\nnew DSACryptoServiceProvider();\n");
    writeFileSync(join(dir, "keys.py"), "priv = ec.generate_private_key(ec.SECP256R1())\n");
    writeFileSync(join(dir, "kex.ts"), "const ecdh = createECDH('prime256v1');\n");
    writeFileSync(join(dir, "Sign.swift"), "let key = P256.Signing.PrivateKey()\n");
    // bait: prose / unrelated identifiers must not match
    writeFileSync(join(dir, "clean.py"), "rsa_is_fine_in_comments = 1\nwindows256 = 2\n");

    const ids = new Set(scanDirectory(dir, "rt").assets.map((a) => a.patternId));
    for (const id of ["rsa-dotnet", "ecc-dotnet", "dsa-dotnet", "ecc-python", "ecc-node-ecdh", "ecc-swift-cryptokit"]) {
      assert.ok(ids.has(id), `expected ${id} to fire`);
    }
    const cleanHits = scanDirectory(dir, "rt2").assets.filter((a) => a.file === "clean.py");
    assert.equal(cleanHits.length, 0, `clean.py should be clean, got: ${cleanHits.map((a) => a.patternId).join(", ")}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("patterns: comment-only crypto mentions do not fire (precision — masks comments, keeps real uses)", () => {
  const dir = mkdtempSync(join(tmpdir(), "qv-prec-"));
  try {
    // Heavy crypto vocabulary, but ONLY in comments — the file performs none.
    writeFileSync(join(dir, "mentions.ts"),
      "// migrating away from RSA and ECDSA toward ML-KEM\n" +
      "/* historical: we used Diffie-Hellman, DSA, mbedtls_rsa_gen_key here */\n" +
      "export const COUNT = 1; // wc_ecc_make_key + ssh-rsa keys were removed\n");
    writeFileSync(join(dir, "notes.py"),
      "# TODO: drop rsa.generate_private_key and the ECDSA path\n" +
      "VALUE = 2  # ssh-rsa and -----BEGIN RSA PRIVATE KEY----- references\n");
    // Real uses (in code, not comments) MUST still fire.
    writeFileSync(join(dir, "real.c"), "mbedtls_rsa_gen_key(&c, rng, NULL, 2048, 65537);\n");

    const assets = scanDirectory(dir, "prec").assets;
    const mentionHits = assets.filter((a) => a.file === "mentions.ts" || a.file === "notes.py");
    assert.equal(mentionHits.length, 0,
      `comment-only crypto mentions must not fire, got: ${mentionHits.map((a) => a.file + ":" + a.patternId).join(", ")}`);
    assert.ok(assets.some((a) => a.file === "real.c" && a.patternId === "rsa-mbedtls"),
      "a real crypto call outside comments must still fire");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("patterns: confidence flags mentions as low and real call-sites as high", () => {
  // Call-sites / key material → high; name-config → medium; bare name/enum → low.
  assert.equal(confidenceFor("rsa-keygen-openssl"), "high");
  assert.equal(confidenceFor("rsa-pem-header"), "high");
  assert.equal(confidenceFor("rsa-mbedtls"), "high");
  assert.equal(confidenceFor("dh-keyexchange"), "medium");
  assert.equal(confidenceFor("jwt-rsa-alg"), "low");
  assert.equal(confidenceFor("ecc-curve-decl"), "low");

  const dir = mkdtempSync(join(tmpdir(), "qv-conf-"));
  try {
    // A real RSA key generation (high) plus a JWT-alg ENUM (a mention, not a use → low).
    writeFileSync(join(dir, "app.ts"),
      "const k = generateKeyPairSync('rsa', { modulusLength: 4096 });\n" +
      'export const SUPPORTED = ["RS256", "ES256"];\n');
    const assets = scanDirectory(dir, "conf").assets;
    assert.ok(
      assets.some((a) => a.patternId === "rsa-keygen-openssl" && a.confidence === "high"),
      "a real RSA call must be high-confidence",
    );
    assert.ok(
      assets.some((a) => a.patternId === "jwt-rsa-alg" && a.confidence === "low"),
      "a JWT-alg enum must be low-confidence (possible mention)",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("patterns: ENG-01a — a crypto name in a prose string is a possible mention (low), real uses unchanged", () => {
  const dir = mkdtempSync(join(tmpdir(), "qv-ctx-"));
  try {
    // Line 1: prose strings naming crypto primitives — mentions, not uses.
    // Line 2: a real Diffie-Hellman call in code — a genuine use.
    // Line 3: a tight algorithm-identifier string (one token) passed as config.
    writeFileSync(join(dir, "app.ts"),
      'const log = "We are migrating away from diffie-hellman and 3DES this quarter";\n' +
      "createDiffieHellman(2048);\n" +
      'const algo = { name: "RSA-OAEP" };\n');
    // Key material embedded in a (wordy) string must STILL be high — never downgraded.
    writeFileSync(join(dir, "leak.ts"),
      'const dump = "here is the leaked key -----BEGIN RSA PRIVATE KEY----- abcdef and more";\n');

    const assets = scanDirectory(dir, "ctx").assets;
    const at = (file: string, patternId: string, line: number) =>
      assets.find((a) => a.file === file && a.patternId === patternId && a.line === line);

    // Same pattern, two contexts: prose string → low; real call → its base (medium).
    assert.equal(at("app.ts", "dh-keyexchange", 1)?.confidence, "low", "diffie-hellman in prose is a mention");
    assert.equal(at("app.ts", "dh-keyexchange", 2)?.confidence, "medium", "a real createDiffieHellman call is unchanged");
    // 3DES named in the same prose string → also a mention.
    assert.equal(at("app.ts", "sym-des-3des", 1)?.confidence, "low", "3DES in prose is a mention");
    // A one-token identifier string is a real config value, not prose → base (high) kept.
    assert.equal(at("app.ts", "rsa-webcrypto", 3)?.confidence, "high", "tight 'RSA-OAEP' token string is a real use");
    // Key material is real wherever it appears — prose context must not downgrade it.
    assert.equal(at("leak.ts", "rsa-pem-header", 1)?.confidence, "high", "an RSA private-key block is high even inside a string");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("patterns: ENG-01a hardening — structural values + real same-line/template calls survive (adversarial-review regressions)", () => {
  const dir = mkdtempSync(join(tmpdir(), "qv-ctx2-"));
  try {
    // (1) SSH public keys as quoted multi-word config values — REAL keys, kept.
    // The canonical `type blob user@host` form is intrinsically ≥3 tokens.
    writeFileSync(join(dir, "keys.yaml"),
      'admin_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDx root@bastion"\n' +
      'node_key: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAy deploy@host"\n');
    // (2) An OpenSSL cipher list — ≥3 tokens but no function words → not prose.
    writeFileSync(join(dir, "tls.yaml"),
      'ciphers: "ECDHE-RSA-AES128-GCM-SHA256 DHE-RSA-AES128-GCM-SHA256 AES128-SHA"\n');
    // (3) A real DH call inside a template-literal interpolation — kept.
    writeFileSync(join(dir, "q.ts"), "const q = `rotate ${createDiffieHellman(2048)} keys now`;\n");
    // (4) Prose mention + real call on the SAME line — the real call is kept.
    writeFileSync(join(dir, "log.ts"),
      'logger.info("rotating the diffie-hellman params now"); createDiffieHellman(2048);\n');

    const assets = scanDirectory(dir, "ctx2").assets;
    const conf = (file: string, patternId: string) =>
      assets.find((a) => a.file === file && a.patternId === patternId)?.confidence;

    // Value-bearing key/cert patterns are never downgraded — recall is preserved.
    assert.equal(conf("keys.yaml", "ssh-rsa-key"), "medium", "a quoted ssh-rsa key is real, not a mention");
    assert.equal(conf("keys.yaml", "ssh-ecdsa-key"), "medium", "a quoted ecdsa-sha2 key is real, not a mention");
    // A structured multi-token value with no function words is not prose.
    assert.equal(conf("tls.yaml", "sym-aes128"), "medium", "a cipher list is structured config, not prose");
    // A real call inside ${...} keeps its confidence (the interpolation is code).
    assert.equal(conf("q.ts", "dh-keyexchange"), "medium", "a real call in a template interpolation is kept");
    // A real call sharing a line with a prose mention of the same family is kept.
    assert.equal(conf("log.ts", "dh-keyexchange"), "medium", "a same-line real call is not stolen by a prose mention");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("scanner: test/example/sample directories are skipped so the grade reflects production code", () => {
  const dir = mkdtempSync(join(tmpdir(), "qv-nonprod-"));
  try {
    for (const d of ["src", "__tests__", "examples", "sample-data", "src/mocks"]) {
      mkdirSync(join(dir, d), { recursive: true });
    }
    const crypto = "mbedtls_rsa_gen_key(&c, rng, NULL, 2048, 65537);\n";
    writeFileSync(join(dir, "src", "app.c"), crypto); // production — must fire
    writeFileSync(join(dir, "__tests__", "x.c"), crypto); // skipped
    writeFileSync(join(dir, "examples", "y.c"), crypto); // skipped
    writeFileSync(join(dir, "sample-data", "z.c"), crypto); // skipped (sample- prefix)
    writeFileSync(join(dir, "src", "mocks", "m.c"), crypto); // skipped (mocks dir)

    const assets = scanDirectory(dir, "nonprod").assets;
    const files = assets.map((a) => a.file);
    assert.ok(files.some((f) => f.includes("app.c")), "production src must be scanned");
    assert.equal(assets.length, 1, `only the production finding should count, got: ${files.join(", ")}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("patterns: embedded C/C++ firmware crypto detectors fire (mbedTLS/wolfSSL/OpenSSL C)", () => {
  const dir = mkdtempSync(join(tmpdir(), "qv-embed-"));
  try {
    writeFileSync(join(dir, "boot.c"),
      "mbedtls_rsa_gen_key(&ctx, rng, NULL, 2048, 65537);\n" +
      "mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, 32, rng, NULL);\n" +
      "mbedtls_dhm_make_public(&dhm, 256, out, olen, rng, NULL);\n");
    writeFileSync(join(dir, "tls.cpp"),
      "wc_MakeRsaKey(&key, 2048, 65537, &rng);\n" +
      "wc_ecc_make_key(&rng, 32, &eccKey);\n");
    writeFileSync(join(dir, "sign.cc"),
      "EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);\n" +
      "EC_KEY *k = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);\n" +
      "DH_generate_key(dh);\n");
    // bait: prose and unrelated identifiers must not fire
    writeFileSync(join(dir, "clean.c"), "// uses aes-256-gcm only\nint mbedtls_aes_setkey_enc = 0;\n");

    const ids = new Set(scanDirectory(dir, "embed").assets.map((a) => a.patternId));
    for (const id of [
      "rsa-mbedtls", "ecc-mbedtls", "dh-mbedtls",
      "rsa-wolfssl", "ecc-wolfssl",
      "rsa-openssl-c", "ecc-openssl-c", "dh-openssl-c",
    ]) {
      assert.ok(ids.has(id), `expected ${id} to fire`);
    }
    const cleanHits = scanDirectory(dir, "embed2").assets.filter((a) => a.file === "clean.c");
    assert.equal(cleanHits.length, 0, `clean.c should be clean, got: ${cleanHits.map((a) => a.patternId).join(", ")}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("patterns: extractKeyBits respects family-specific valid sizes", () => {
  assert.equal(extractKeyBits("modulusLength: 2048", "RSA"), 2048);
  assert.equal(extractKeyBits("rsa_bits = 1024", "RSA"), 1024);
  assert.equal(extractKeyBits("ecdsa curve P-256", "ECC"), 256);
  // digits embedded in a word (secp256r1) are NOT a bounded token -> null
  assert.equal(extractKeyBits("secp256r1", "ECC"), null);
  // 2048 is not a valid ECC curve size -> null
  assert.equal(extractKeyBits("modulusLength: 2048", "ECC"), null);
  // symmetric only accepts 128/256
  assert.equal(extractKeyBits("aes-128-gcm", "SymmetricLegacy"), 128);
  assert.equal(extractKeyBits("no digits here", "RSA"), null);
});

// ------------------------------------------------------------- CSV export
test("csv: header row + RFC-4180 escaping of commas, quotes, and newlines", () => {
  const csv = assetsToCsv([
    asset({ family: "RSA", file: "src/a,b.ts", snippet: 'say "hi"', algorithm: "RSA" }),
  ]);
  const lines = csv.split("\r\n");
  assert.match(lines[0], /^file,line,family,algorithm,/);
  // comma-containing field is quoted; embedded quotes are doubled
  assert.ok(lines[1].includes('"src/a,b.ts"'), lines[1]);
  assert.ok(lines[1].includes('"say ""hi"""'), lines[1]);
  assert.equal(csv.endsWith("\r\n"), true);
});

test("csv (⚑4): quantum_exposure column distinguishes AES-128 from Shor-broken findings", () => {
  const csv = assetsToCsv([
    asset({ family: "SymmetricLegacy", algorithm: "AES-128", patternId: "sym-aes128" }),
    asset({ family: "RSA", algorithm: "RSA", patternId: "rsa-keygen-openssl" }),
  ]);
  const lines = csv.trim().split("\r\n");
  const headers = lines[0].split(",");
  const col = headers.indexOf("quantum_exposure");
  assert.ok(col >= 0, "quantum_exposure column present");
  assert.equal(lines[1].split(",")[col], "grover-weakened");
  assert.equal(lines[2].split(",")[col], "shor-broken");
});

test("csv: empty inventory still emits a header row", () => {
  const csv = assetsToCsv([]);
  assert.match(csv, /^file,line,family,/);
  assert.equal(csv.trim().split("\r\n").length, 1);
});

// ------------------------------------------------------------- CBOM (CycloneDX)
test("cbom: emits a valid CycloneDX 1.6 cryptography bill of materials", () => {
  const cbom = assetsToCbom(
    [
      asset({ family: "RSA", algorithm: "RSA", keyBits: 2048, file: "a.ts", line: 3, patternId: "rsa", quantumVulnerable: true }),
      asset({ family: "HashLegacy", algorithm: "MD5/SHA-1", file: "b.ts", line: 9, patternId: "hash", quantumVulnerable: true }),
    ],
    { target: "/repo" },
  ) as any;

  assert.equal(cbom.bomFormat, "CycloneDX");
  assert.equal(cbom.specVersion, "1.6");
  assert.match(cbom.serialNumber, /^urn:uuid:/);
  assert.equal(cbom.metadata.component.name, "/repo");
  assert.equal(cbom.components.length, 2);

  // Components are sorted by bom-ref, so locate by name rather than index.
  const rsa = cbom.components.find((c: any) => c.name === "RSA");
  assert.ok(rsa, "RSA component present");
  assert.equal(rsa.type, "cryptographic-asset");
  assert.equal(rsa.cryptoProperties.assetType, "algorithm");
  assert.equal(rsa.cryptoProperties.oid, "1.2.840.113549.1.1.1"); // verified rsaEncryption OID
  const rsaAp = rsa.cryptoProperties.algorithmProperties;
  assert.equal(rsaAp.primitive, "pke");
  assert.equal(rsaAp.parameterSetIdentifier, "2048");
  // RSA key size isn't observed from a usage scan, so classical strength is
  // honestly omitted rather than assumed.
  assert.equal(rsaAp.classicalSecurityLevel, undefined);
  assert.ok(rsaAp.cryptoFunctions.includes("sign") && rsaAp.cryptoFunctions.includes("keygen"));
  // quantum-vulnerable asymmetric -> NIST quantum security category 0
  assert.equal(rsaAp.nistQuantumSecurityLevel, 0);
  assert.equal(rsa.evidence.occurrences[0].location, "a.ts");
  assert.equal(rsa.evidence.occurrences[0].line, 3);

  // Lumped MD5/SHA-1 maps to "hash", emits 0-bit strength, and withholds an OID.
  const hash = cbom.components.find((c: any) => c.name === "MD5/SHA-1");
  assert.equal(hash.cryptoProperties.algorithmProperties.primitive, "hash");
  assert.equal(hash.cryptoProperties.algorithmProperties.classicalSecurityLevel, 0);
  assert.equal(hash.cryptoProperties.oid, undefined);

  // Dependency graph: the application consumes every discovered algorithm.
  assert.equal(cbom.dependencies[0].ref, "application:/repo");
  assert.equal(cbom.dependencies[0].dependsOn.length, 2);

  // The document conforms to our CycloneDX 1.6 validator.
  assert.deepEqual(validateCbom(cbom), { valid: true, errors: [] });
});

test("cbom: serial number is deterministic for the same inventory, distinct otherwise", () => {
  const findings = [asset({ family: "RSA", algorithm: "RSA", file: "a.ts", line: 3, patternId: "rsa" })];
  const a = assetsToCbom(findings, { target: "/repo", generatedAt: "2026-01-01T00:00:00.000Z" }) as any;
  const b = assetsToCbom(findings, { target: "/repo", generatedAt: "2030-09-09T00:00:00.000Z" }) as any;
  // Same findings + target -> identical serial, even at a different export time.
  assert.equal(a.serialNumber, b.serialNumber);
  const other = assetsToCbom(findings, { target: "/other-repo" }) as any;
  assert.notEqual(a.serialNumber, other.serialNumber);
});

test("cbom: AES-128 carries NIST quantum category 1 (Grover only square-roots strength)", () => {
  const cbom = assetsToCbom([asset({ family: "SymmetricLegacy", algorithm: "AES-128", patternId: "aes" })]) as any;
  const aes = cbom.components[0].cryptoProperties.algorithmProperties;
  assert.equal(aes.primitive, "block-cipher");
  assert.equal(aes.nistQuantumSecurityLevel, 1);
  assert.equal(aes.classicalSecurityLevel, 128);
});

test("cbom (⚑4): every component carries its honest quantumExposure tier property", () => {
  const cbom = assetsToCbom([
    asset({ family: "RSA", algorithm: "RSA", file: "a.ts", patternId: "rsa" }),
    asset({ family: "SymmetricLegacy", algorithm: "AES-128", file: "b.ts", patternId: "sym-aes128" }),
    asset({ family: "SymmetricLegacy", algorithm: "DES/3DES", file: "c.ts", patternId: "sym-des-3des" }),
  ]) as any;
  const tierOf = (name: string) =>
    cbom.components.find((c: any) => c.name === name)
      .properties.find((p: any) => p.name === "quantumvault:quantumExposure")?.value;
  assert.equal(tierOf("RSA"), "shor-broken");
  assert.equal(tierOf("AES-128"), "grover-weakened");
  assert.equal(tierOf("DES/3DES"), "classically-weak");
  assert.equal(validateCbom(cbom).valid, true);
});

test("cbom: validator rejects a non-conformant document", () => {
  const broken = {
    bomFormat: "CycloneDX",
    specVersion: "1.5", // wrong spec version
    serialNumber: "not-a-urn",
    version: 1,
    metadata: { timestamp: "2026-01-01T00:00:00.000Z" },
    components: [
      { type: "library", "bom-ref": "x", cryptoProperties: { assetType: "algorithm", algorithmProperties: { primitive: "made-up", nistQuantumSecurityLevel: 9 } } },
    ],
    dependencies: [{ ref: "ghost" }],
  };
  const result = validateCbom(broken);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("specVersion")));
  assert.ok(result.errors.some((e) => e.includes("serialNumber")));
  assert.ok(result.errors.some((e) => e.includes("primitive")));
  assert.ok(result.errors.some((e) => e.includes("nistQuantumSecurityLevel")));
  assert.ok(result.errors.some((e) => e.includes("does not resolve")));
});

test("cbom: empty inventory still produces a well-formed, conformant BOM", () => {
  const cbom = assetsToCbom([]) as any;
  assert.equal(cbom.bomFormat, "CycloneDX");
  assert.ok(Array.isArray(cbom.components));
  assert.equal(cbom.components.length, 0);
  assert.equal(validateCbom(cbom).valid, true);
});

// ------------------------------------------------------------- SARIF
test("sarif: emits a valid SARIF 2.1.0 log with rules, results, and levels", () => {
  const rsa = scoreAsset(asset({ family: "RSA", patternId: "rsa-pem-header", file: "auth/key.pem", algorithm: "RSA", line: 2 }));
  const a1 = asset({ family: "RSA", patternId: "rsa-pem-header", file: "auth/key.pem", algorithm: "RSA", line: 2 });
  a1.risk = rsa;
  const sarif = assetsToSarif([a1]) as any;

  assert.equal(sarif.version, "2.1.0");
  const driver = sarif.runs[0].tool.driver;
  assert.equal(driver.name, "UniQueS");
  assert.ok(driver.rules.some((r: any) => r.id === "rsa-pem-header"));

  const result = sarif.runs[0].results[0];
  assert.equal(result.ruleId, "rsa-pem-header");
  assert.ok(["error", "warning", "note"].includes(result.level));
  assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, "auth/key.pem");
  assert.equal(result.locations[0].physicalLocation.region.startLine, 2);
  // GitHub security-severity is a 0–10 string derived from the risk score
  assert.match(result.properties["security-severity"], /^\d+(\.\d)?$/);
});

test("sarif (⚑4): AES-128 message is margin-reduction copy, not break language; tier is a property", () => {
  const aes = asset({ family: "SymmetricLegacy", algorithm: "AES-128", patternId: "sym-aes128", pqcReplacement: "AES-256-GCM" });
  aes.risk = scoreAsset(aes);
  const rsa = asset({ family: "RSA", algorithm: "RSA", patternId: "rsa-keygen-openssl" });
  rsa.risk = scoreAsset(rsa);
  const sarif = assetsToSarif([aes, rsa]) as any;
  const [aesR, rsaR] = sarif.runs[0].results;
  assert.match(aesR.message.text, /Grover-weakened/);
  assert.match(aesR.message.text, /normal upgrade cycle/);
  assert.doesNotMatch(aesR.message.text, /is quantum-vulnerable/);
  assert.equal(aesR.properties.quantumExposure, "grover-weakened");
  // Shor-broken findings keep the break language.
  assert.match(rsaR.message.text, /is quantum-vulnerable/);
  assert.equal(rsaR.properties.quantumExposure, "shor-broken");
});

test("sarif: critical/high map to error level", () => {
  const a = asset({ family: "RSA", file: "services/auth/payment/k.pem", patternId: "rsa-pem-header", algorithm: "RSA" });
  a.risk = scoreAsset(a);
  const sarif = assetsToSarif([a]) as any;
  // a payment/auth RSA key scores critical -> error
  assert.equal(sarif.runs[0].results[0].level, "error");
});

// ------------------------------------------------------------- OpenAPI
test("openapi: emits a valid 3.1 document covering the key endpoints", () => {
  const doc = openApiDocument() as any;
  assert.equal(doc.openapi, "3.1.0");
  assert.equal(doc.info.title, "UniQueS API");
  assert.equal(doc.servers[0].url, "/api");
  assert.ok(doc.components.securitySchemes.bearerAuth);
  // representative endpoints across the surface are described
  for (const p of ["/health", "/scans", "/scans/git", "/cbom.json", "/sarif.json", "/compliance/{framework}", "/assets/{id}/status"]) {
    assert.ok(doc.paths[p], `missing path: ${p}`);
  }
  // a mutating endpoint requires bearer auth
  assert.deepEqual(doc.paths["/scans"].post.security, [{ bearerAuth: [] }]);
});

// ------------------------------------------------------------- rate limiter
test("rateLimiter: allows up to max, blocks the overflow, recovers after the window", () => {
  let now = 1000;
  const rl = new RateLimiter(3, 1000, () => now);
  assert.equal(rl.check("ip1"), true);
  assert.equal(rl.check("ip1"), true);
  assert.equal(rl.check("ip1"), true);
  assert.equal(rl.check("ip1"), false, "4th within window is blocked");
  // a different key is tracked independently
  assert.equal(rl.check("ip2"), true);
  // advance past the window -> the old hits expire and requests are allowed again
  now += 1001;
  assert.equal(rl.check("ip1"), true);
});

test("rateLimit middleware blocks after max per key and isolates keys", () => {
  const mw = rateLimit(2, 1000, (req) => req.orgId);
  const run = (org: string) => {
    const req = { orgId: org, ip: "1.1.1.1" } as unknown as Request;
    let statusCode = 0;
    let nexted = false;
    const res = {
      status(c: number) {
        statusCode = c;
        return res;
      },
      json() {
        return res;
      },
    } as unknown as Response;
    mw(req, res, () => {
      nexted = true;
    });
    return { nexted, statusCode };
  };

  assert.equal(run("orgA").nexted, true);
  assert.equal(run("orgA").nexted, true);
  const third = run("orgA");
  assert.equal(third.nexted, false, "3rd request for orgA is blocked");
  assert.equal(third.statusCode, 429);
  // a different org is tracked independently and still allowed
  assert.equal(run("orgB").nexted, true);
});

// ------------------------------------------------------------- repo normalizer (SSRF guard)
test("repo: owner/repo shorthand normalizes to a GitHub https clone url", () => {
  const r = normalizeRepo("openssl/openssl");
  assert.equal(r.cloneUrl, "https://github.com/openssl/openssl.git");
  assert.equal(r.label, "github.com/openssl/openssl");
});

test("repo: full https URLs are accepted and www / .git are stripped", () => {
  assert.equal(normalizeRepo("https://www.gitlab.com/group/proj.git").cloneUrl, "https://gitlab.com/group/proj.git");
  assert.equal(normalizeRepo("https://bitbucket.org/team/repo").label, "bitbucket.org/team/repo");
});

test("repo: rejects non-https, unknown hosts, and embedded credentials", () => {
  assert.throws(() => normalizeRepo("http://github.com/a/b"), /https/);
  assert.throws(() => normalizeRepo("https://evil.example.com/a/b"), /unsupported host/);
  assert.throws(() => normalizeRepo("https://user:pass@github.com/a/b"), /credentials/);
  assert.throws(() => normalizeRepo(""), /required/);
});

// ------------------------------------------------------------- scanner (integration)
test("scanner: discovers crypto assets in a temp source tree and skips junk dirs", () => {
  const dir = mkdtempSync(join(tmpdir(), "qv-test-"));
  try {
    writeFileSync(
      join(dir, "server.ts"),
      ["const k = generateKeyPairSync('rsa', { modulusLength: 2048 });", "// secp256r1 curve in use"].join("\n"),
    );
    writeFileSync(join(dir, "key.pem"), "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n");
    // binary-ish and ignored dirs must NOT be scanned
    mkdirSync(join(dir, "node_modules"));
    writeFileSync(join(dir, "node_modules", "lib.ts"), "createDiffieHellman(2048)");
    writeFileSync(join(dir, "image.png"), "\x00\x01\x02PNGbinary");

    const { job, assets } = scanDirectory(dir, "scan-test");
    assert.equal(job.status, "completed");
    assert.ok(assets.length >= 2, `expected >=2 assets, got ${assets.length}`);
    // RSA PEM header must be detected as a critical-family asset
    assert.ok(assets.some((a) => a.patternId === "rsa-pem-header"));
    // nothing from node_modules should appear
    assert.ok(!assets.some((a) => a.file.includes("node_modules")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("scanner: PKCS#8 keys are labeled Asymmetric, not mislabeled RSA", () => {
  const dir = mkdtempSync(join(tmpdir(), "qv-pkcs8-"));
  try {
    // PKCS#1 header — unambiguously RSA.
    writeFileSync(join(dir, "rsa.pem"), "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n");
    // PKCS#8 header — algorithm not visible (this is what an Ed25519/EC key uses).
    writeFileSync(join(dir, "pkcs8.pem"), "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n");

    const { assets } = scanDirectory(dir, "scan-pkcs8");
    const rsa = assets.find((a) => a.file.endsWith("rsa.pem"));
    const pkcs8 = assets.find((a) => a.file.endsWith("pkcs8.pem"));

    assert.equal(rsa?.family, "RSA", "PKCS#1 header should remain RSA");
    assert.ok(pkcs8, "PKCS#8 key should still be detected");
    assert.equal(pkcs8?.family, "Asymmetric", "PKCS#8 header must NOT be asserted as RSA");
    assert.equal(pkcs8?.patternId, "pkcs8-pem-private-key");
    // A PKCS#8 file must never be claimed to be RSA — that was the bug.
    assert.ok(!assets.some((a) => a.file.endsWith("pkcs8.pem") && a.family === "RSA"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("scanner: .quantumvaultignore baselines matching paths (prefix-based)", () => {
  const dir = mkdtempSync(join(tmpdir(), "qv-ign-"));
  try {
    mkdirSync(join(dir, "app"));
    mkdirSync(join(dir, "third_party"));
    writeFileSync(join(dir, "app", "auth.ts"), "generateKeyPairSync('rsa', { modulusLength: 2048 });\n");
    writeFileSync(join(dir, "third_party", "lib.ts"), "createDiffieHellman(2048);\n");

    // No ignore file → both directories are scanned.
    const before = scanDirectory(dir, "s1").assets;
    assert.ok(before.some((a) => a.file.includes("app")));
    assert.ok(before.some((a) => a.file.includes("third_party")));

    // Baseline out the vendored directory.
    writeFileSync(join(dir, ".quantumvaultignore"), "# vendored deps\nthird_party\n");
    const after = scanDirectory(dir, "s2").assets;
    assert.ok(after.some((a) => a.file.includes("app")), "app findings retained");
    assert.ok(!after.some((a) => a.file.includes("third_party")), "third_party findings suppressed");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("scanner: new multi-language patterns fire on real constructs but not on bait text", () => {
  const dir = mkdtempSync(join(tmpdir(), "qv-test-multi-"));
  try {
    // --- Real quantum-vulnerable constructs across languages ---
    writeFileSync(
      join(dir, "signer.rb"),
      [
        "key = OpenSSL::PKey::RSA.new(2048)",
        "legacy = OpenSSL::PKey::DSA.new(1024)",
        'curve = OpenSSL::PKey::EC.new("prime256v1")',
      ].join("\n"),
    );
    writeFileSync(
      join(dir, "Token.java"),
      'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");',
    );
    writeFileSync(
      join(dir, "batch.java"),
      'KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");',
    );
    writeFileSync(
      join(dir, "onboard.php"),
      "$k = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA]);",
    );
    writeFileSync(
      join(dir, "vault.rs"),
      "let master = RsaPrivateKey::new(&mut rng, 3072).unwrap();",
    );
    writeFileSync(
      join(dir, "backup.key"),
      "-----BEGIN PGP PRIVATE KEY BLOCK-----\nzZZZ\n-----END PGP PRIVATE KEY BLOCK-----\n",
    );

    // --- Bait files: superficially crypto-ish text that must NOT match ---
    // Ruby bait: mentions classes/identifiers but never the exact constructors.
    writeFileSync(
      join(dir, "bait.rb"),
      [
        "# notes mentioning AES256 and WINDOWS256 and ordinary identifiers",
        "MyRSAHelper = Object.new # a custom helper, not the OpenSSL constructor",
        "describe_rsa_options('docs about RSA but no construction')",
        "OpenSSL::PKey::RSA.generate(2048) # generate, not .new",
        "RsaPrivateKeyDocs = 'identifier mention only, no :: accessor'",
      ].join("\n"),
    );
    // PHP/Java/Rust bait: near-miss tokens in their own languages.
    writeFileSync(
      join(dir, "bait.php"),
      [
        "<?php",
        "openssl_pkey_export_to_file($x, 'out.pem'); // different fn, no KEYTYPE_RSA",
        "$type = 'OPENSSL_KEYTYPE_RSA'; // a string constant, no openssl_pkey_new call",
      ].join("\n"),
    );
    writeFileSync(
      join(dir, "bait.java"),
      [
        "int ekgPairGenerator = 1; // not a real KeyPairGenerator",
        'String alg = "RSA"; // a literal, no getInstance call',
      ].join("\n"),
    );
    writeFileSync(
      join(dir, "bait.txt"),
      "BEGIN PGP PUBLIC KEY BLOCK is a different, non-private header\n",
    );

    const { assets } = scanDirectory(dir, "scan-multi");
    const idsByFile = (f: string) =>
      new Set(assets.filter((a) => a.file === f).map((a) => a.patternId));

    // Each new construct fires exactly its intended pattern.
    assert.ok(idsByFile("signer.rb").has("rsa-ruby-openssl"));
    assert.ok(idsByFile("signer.rb").has("dsa-ruby-openssl"));
    assert.ok(idsByFile("signer.rb").has("ecc-ruby-openssl"));
    assert.ok(idsByFile("Token.java").has("rsa-java-keypairgen"));
    assert.ok(idsByFile("batch.java").has("dsa-java-keypairgen"));
    assert.ok(idsByFile("onboard.php").has("rsa-php-openssl"));
    assert.ok(idsByFile("vault.rs").has("rsa-rust-crate"));
    assert.ok(idsByFile("backup.key").has("rsa-pgp-private-block"));

    // ZERO findings on any bait file — the zero-false-positive guarantee.
    const baitFindings = assets.filter((a) => a.file.startsWith("bait."));
    assert.equal(baitFindings.length, 0, `bait produced findings: ${JSON.stringify(baitFindings.map((a) => `${a.file}:${a.patternId}`))}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
