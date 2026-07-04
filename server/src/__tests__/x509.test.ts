import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, rmSync, readdirSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  parseCertificate,
  extractPemCertificates,
  X509_PARSED_PATTERN_ID,
  X509_UNPARSEABLE_PATTERN_ID,
} from "../discovery/x509.js";
import { scanDirectory } from "../discovery/scanner.js";
import { assetsToCbom, validateCbom } from "../discovery/cbom.js";

/**
 * ENG-02 — X.509 certificate discovery tests.
 *
 * PEM fixtures under fixtures/certs/ are openssl-generated (real DER, real
 * validity windows); the ML-DSA certificate is hand-crafted in-test because
 * openssl cannot issue one. Fixtures live under __tests__, which the production
 * scan walk skips, so the repo's self-scan stays clean honestly.
 */

const certsDir = new URL("./fixtures/certs/", import.meta.url).pathname;
const pem = (name: string) => readFileSync(join(certsDir, name), "utf8");
const firstDer = (name: string) => {
  const blocks = extractPemCertificates(pem(name));
  assert.ok(blocks.length > 0 && blocks[0].der, `${name}: no decodable PEM block`);
  return blocks[0].der!;
};

// ── minimal DER builder (test-only) for certificates openssl cannot mint ─────

function derLen(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  let v = n;
  while (v > 0) { bytes.unshift(v & 0xff); v >>= 8; }
  return [0x80 | bytes.length, ...bytes];
}
const tlv = (tag: number, content: number[]): number[] => [tag, ...derLen(content.length), ...content];
const seq = (...parts: number[][]): number[] => tlv(0x30, parts.flat());
function oid(dotted: string): number[] {
  const parts = dotted.split(".").map(Number);
  const body = [parts[0] * 40 + parts[1]];
  for (const p of parts.slice(2)) {
    const enc: number[] = [p & 0x7f];
    let v = p >> 7;
    while (v > 0) { enc.unshift(0x80 | (v & 0x7f)); v >>= 7; }
    body.push(...enc);
  }
  return tlv(0x06, body);
}
const utf8 = (s: string): number[] => tlv(0x0c, [...Buffer.from(s, "utf8")]);
const cnName = (cn: string): number[] => seq(tlv(0x31, seq(oid("2.5.4.3"), utf8(cn))));
const bitString = (bytes: number[]): number[] => tlv(0x03, [0x00, ...bytes]);
const integer = (bytes: number[]): number[] => tlv(0x02, bytes);
const time = (tag: number, s: string): number[] => [tag, s.length, ...[...s].map((c) => c.charCodeAt(0))];

/** A structurally valid ML-DSA-65 certificate (OID 2.16.840.1.101.3.4.3.18 for
 *  both key and signature; dummy key/signature bytes — structure, not crypto). */
function mlDsa65CertDer(): Uint8Array {
  const mlDsa65 = "2.16.840.1.101.3.4.3.18";
  const algId = seq(oid(mlDsa65));
  const tbs = seq(
    tlv(0xa0, integer([0x02])), // [0] version v3
    integer([0x01]), // serialNumber
    algId, // signature
    cnName("mldsa.uniques.test"), // issuer
    seq(time(0x17, "260101000000Z"), time(0x18, "20360101000000Z")), // UTCTime + GeneralizedTime
    cnName("mldsa.uniques.test"), // subject
    seq(algId, bitString(new Array(64).fill(0xab))), // subjectPublicKeyInfo
  );
  return Uint8Array.from(seq(tbs, algId, bitString([0x01, 0x02, 0x03])));
}

// ── parser unit tests ─────────────────────────────────────────────────────────

test("x509: RSA-2048 SHA-256 self-signed — key bits (sign-byte aware), CN, validity", () => {
  const res = parseCertificate(firstDer("rsa2048-sha256.pem"));
  assert.ok(res.ok, !res.ok ? res.reason : "");
  assert.equal(res.cert.keyAlgorithm, "RSA-2048");
  assert.equal(res.cert.keyFamily, "RSA");
  assert.equal(res.cert.keyBits, 2048); // leading 0x00 sign byte must not add 8 bits
  assert.equal(res.cert.signatureAlgorithm, "SHA-256 with RSA");
  assert.equal(res.cert.quantumVulnerable, true);
  assert.equal(res.cert.subject, "rsa.uniques.test");
  assert.equal(res.cert.issuer, "rsa.uniques.test");
  assert.equal(res.cert.expired, false);
  assert.match(res.cert.notAfter ?? "", /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
});

test("x509: ECDSA P-256 — named curve from SPKI params", () => {
  const res = parseCertificate(firstDer("ecdsa-p256.pem"));
  assert.ok(res.ok);
  assert.equal(res.cert.keyAlgorithm, "ECDSA P-256");
  assert.equal(res.cert.keyFamily, "ECC");
  assert.equal(res.cert.keyBits, 256);
  assert.equal(res.cert.signatureAlgorithm, "ECDSA with SHA-256");
});

test("x509: Ed25519 — recognized, classical (Shor breaks it)", () => {
  const res = parseCertificate(firstDer("ed25519.pem"));
  assert.ok(res.ok);
  assert.equal(res.cert.keyAlgorithm, "Ed25519");
  assert.equal(res.cert.keyFamily, "ECC");
  assert.equal(res.cert.quantumVulnerable, true);
});

test("x509: RSA-PSS signature — hash read from the AlgorithmIdentifier params", () => {
  const res = parseCertificate(firstDer("rsa-pss.pem"));
  assert.ok(res.ok);
  assert.equal(res.cert.signatureAlgorithm, "RSA-PSS (SHA-256)");
  assert.equal(res.cert.keyBits, 2048);
});

test("x509: expired certificate — notAfter in the past flips certExpired", () => {
  const res = parseCertificate(firstDer("expired.pem"));
  assert.ok(res.ok);
  assert.equal(res.cert.notAfter, "2021-01-01T00:00:00Z");
  assert.equal(res.cert.expired, true);
  // and with a clock before expiry it is NOT expired (pure function of `now`)
  const before = parseCertificate(firstDer("expired.pem"), new Date("2020-06-01T00:00:00Z"));
  assert.ok(before.ok);
  assert.equal(before.cert.expired, false);
});

test("x509: ML-DSA-65 certificate (hand-crafted DER) is recognized as post-quantum SAFE", () => {
  const res = parseCertificate(mlDsa65CertDer());
  assert.ok(res.ok, !res.ok ? res.reason : "");
  assert.equal(res.cert.keyAlgorithm, "ML-DSA-65");
  assert.equal(res.cert.keyFamily, "PQC");
  assert.equal(res.cert.signatureAlgorithm, "ML-DSA-65");
  assert.equal(res.cert.quantumVulnerable, false); // PQC key + PQC signature
  assert.equal(res.cert.subject, "mldsa.uniques.test");
  assert.equal(res.cert.notBefore, "2026-01-01T00:00:00Z"); // UTCTime arm
  assert.equal(res.cert.notAfter, "2036-01-01T00:00:00Z"); // GeneralizedTime arm
});

test("x509: parser is total — malformed inputs return typed failures, never throw", () => {
  assert.equal(parseCertificate(new Uint8Array(0)).ok, false);
  assert.equal(parseCertificate(Uint8Array.from([0x30, 0x84, 0xff, 0xff, 0xff, 0xff])).ok, false); // huge length
  assert.equal(parseCertificate(Uint8Array.from([0x30, 0x80, 0x00, 0x00])).ok, false); // indefinite length (BER)
  assert.equal(parseCertificate(readFileSync(join(certsDir, "corrupt.der"))).ok, false); // truncated real cert
  assert.equal(parseCertificate(Uint8Array.from(new Array(64).fill(0x30))).ok, false); // nested garbage
  const big = new Uint8Array(200_001).fill(0x30);
  assert.equal(parseCertificate(big).ok, false); // over the size cap
});

test("x509: extractPemCertificates finds every block in a chain with correct lines", () => {
  const blocks = extractPemCertificates(pem("chain.pem"));
  assert.equal(blocks.length, 2);
  assert.equal(blocks[0].line, 1);
  assert.ok(blocks[1].line > blocks[0].line);
  assert.ok(blocks[0].der && blocks[1].der);
});

// ── scanner integration ───────────────────────────────────────────────────────

function scanFixture(files: Record<string, string | Buffer>) {
  const dir = mkdtempSync(join(tmpdir(), "qv-x509-"));
  try {
    for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content);
    return scanDirectory(dir, "x509test").assets;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("scanner: a 2-cert chain file = one enriched asset per certificate, generic finding deduped", () => {
  const assets = scanFixture({ "chain.pem": pem("chain.pem") });
  const parsed = assets.filter((a) => a.patternId === X509_PARSED_PATTERN_ID);
  assert.equal(parsed.length, 2, "one asset per certificate in the chain");
  // DEDUPE (the v0.3.7 scar): the generic PEM-header regex must NOT double-count
  // a block the parser already turned into an enriched asset.
  assert.equal(assets.filter((a) => a.patternId === "x509-cert-body").length, 0);
  const [rsa, ec] = parsed;
  assert.equal(rsa.family, "RSA");
  assert.equal(rsa.keyBits, 2048);
  assert.equal(rsa.confidence, "high"); // a parsed cert is not a mention
  assert.equal(rsa.certSubject, "rsa.uniques.test");
  assert.equal(rsa.certExpired, false);
  assert.match(rsa.certNotAfter ?? "", /^\d{4}/);
  assert.equal(ec.family, "ECC");
  assert.ok(ec.line > rsa.line, "second cert anchors to its own header line");
});

test("scanner: binary DER file parses via the pre-check (would otherwise be skipped as binary)", () => {
  const assets = scanFixture({ "server.der": readFileSync(join(certsDir, "rsa2048-sha256.der")) });
  assert.equal(assets.length, 1);
  assert.equal(assets[0].patternId, X509_PARSED_PATTERN_ID);
  assert.equal(assets[0].family, "RSA");
  assert.equal(assets[0].keyBits, 2048);
  assert.equal(assets[0].quantumVulnerable, true);
});

test("scanner: an unparseable binary cert file surfaces as a review-manually finding, never silently dropped", () => {
  const assets = scanFixture({ "broken.crt": readFileSync(join(certsDir, "corrupt.der")) });
  assert.equal(assets.length, 1);
  assert.equal(assets[0].patternId, X509_UNPARSEABLE_PATTERN_ID);
  assert.equal(assets[0].family, "Asymmetric");
  assert.equal(assets[0].quantumVulnerable, true); // fail closed
  assert.equal(assets[0].confidence, "low"); // per the ambiguous-PKCS#8 precedent
});

test("scanner: binary DER MISLABELED as .pem or .key still parses — a common `openssl -outform DER -out cert.pem` export must not scan clean", () => {
  const der = readFileSync(join(certsDir, "rsa2048-sha256.der"));
  for (const name of ["binary-cert-named.pem", "binary.key"]) {
    const assets = scanFixture({ [name]: der });
    assert.equal(assets.length, 1, `${name}: exactly one asset`);
    assert.equal(assets[0].patternId, X509_PARSED_PATTERN_ID);
    assert.equal(assets[0].keyBits, 2048);
  }
  // non-cert binary under .key: still surfaced for review, never silently skipped
  const garbage = scanFixture({ "garbage.key": Buffer.from([0x00, 0x01, 0x02, 0xff, 0x30, 0x00]) });
  assert.equal(garbage.length, 1);
  assert.equal(garbage[0].patternId, X509_UNPARSEABLE_PATTERN_ID);
});

test("scanner: an UNREADABLE cert file (EACCES) fails closed — counted and surfaced, not vanished", (t) => {
  if (typeof process.getuid === "function" && process.getuid() === 0) {
    t.skip("running as root: chmod 000 does not block reads");
    return;
  }
  const dir = mkdtempSync(join(tmpdir(), "qv-x509-"));
  try {
    writeFileSync(join(dir, "unreadable.crt"), pem("rsa2048-sha256.pem"));
    chmodSync(join(dir, "unreadable.crt"), 0o000);
    const { job, assets } = scanDirectory(dir, "x509test");
    assert.equal(job.filesScanned, 1, "the unreadable cert file is counted, not invisible");
    assert.equal(assets.length, 1);
    assert.equal(assets[0].patternId, X509_UNPARSEABLE_PATTERN_ID);
    assert.match(assets[0].snippet, /unreadable/);
  } finally {
    chmodSync(join(dir, "unreadable.crt"), 0o600);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("scanner: headerless base64 DER in a cert extension parses; unrecognizable text there is surfaced", () => {
  const der = readFileSync(join(certsDir, "rsa2048-sha256.der"));
  // some keytool/config-management pipelines emit the base64 of the DER with no PEM armor
  const b64 = der.toString("base64").replace(/(.{64})/g, "$1\n") + "\n";
  const parsed = scanFixture({ "base64-noarmor.der": b64 });
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].patternId, X509_PARSED_PATTERN_ID);
  assert.equal(parsed[0].keyBits, 2048);
  // a cert-extension text file that is neither PEM nor base64 DER: review manually
  const junk = scanFixture({ "notes.der": "this is not a certificate at all\n" });
  assert.equal(junk.length, 1);
  assert.equal(junk[0].patternId, X509_UNPARSEABLE_PATTERN_ID);
});

test("scanner: an expired certificate carries certExpired=true", () => {
  const assets = scanFixture({ "old.pem": pem("expired.pem") });
  const parsed = assets.find((a) => a.patternId === X509_PARSED_PATTERN_ID);
  assert.ok(parsed);
  assert.equal(parsed.certExpired, true);
});

test("scanner: a PQC (ML-DSA) certificate is inventoried SAFE — quantumVulnerable false", () => {
  const der = Buffer.from(mlDsa65CertDer());
  const pemBody = der.toString("base64").replace(/(.{64})/g, "$1\n").trimEnd();
  const pemText = `-----BEGIN CERTIFICATE-----\n${pemBody}\n-----END CERTIFICATE-----\n`;
  const variants: Array<Record<string, string | Buffer>> = [{ "pqc.pem": pemText }, { "pqc.der": der }];
  for (const file of variants) {
    const assets = scanFixture(file);
    assert.equal(assets.length, 1);
    assert.equal(assets[0].patternId, X509_PARSED_PATTERN_ID);
    assert.equal(assets[0].family, "PQC");
    assert.equal(assets[0].quantumVulnerable, false);
    assert.match(assets[0].algorithm, /ML-DSA-65/);
  }
});

test("scanner: a certificate embedded in source (a .ts string literal) still parses and dedupes", () => {
  const body = pem("ecdsa-p256.pem").trim().split("\n").join("\\n");
  const assets = scanFixture({ "cert.ts": `export const CA_CERT = "${body}";\n` });
  const parsed = assets.filter((a) => a.patternId === X509_PARSED_PATTERN_ID);
  assert.equal(parsed.length, 1);
  assert.equal(assets.filter((a) => a.patternId === "x509-cert-body").length, 0);
});

// ── CBOM (Part C) — structural guard; official-schema conformance lives in
//    cbom-schema.test.ts ─────────────────────────────────────────────────────

test("cbom: certificate and protocol assets emit the CycloneDX 1.6 shapes and pass the structural guard", () => {
  const assets = scanFixture({
    "chain.pem": pem("chain.pem"),
    "nginx.conf": "ssl_protocols TLSv1 TLSv1.1;\nssl_ciphers RC4-SHA;\n",
    "sshd_config": "KexAlgorithms ecdh-sha2-nistp256,diffie-hellman-group14-sha256\n",
  });
  const cbom = assetsToCbom(assets, { target: "/repo", generatedAt: "2026-07-03T00:00:00.000Z" }) as any;
  const v = validateCbom(cbom);
  assert.ok(v.valid, v.errors.join("\n"));
  const byType = (t: string) =>
    cbom.components.filter((c: any) => c.cryptoProperties.assetType === t);
  const certs = byType("certificate");
  assert.equal(certs.length, 2);
  assert.ok(certs.every((c: any) => c.cryptoProperties.certificateProperties.certificateFormat === "X.509"));
  assert.ok(certs.every((c: any) => typeof c.cryptoProperties.certificateProperties.subjectName === "string"));
  assert.ok(certs.every((c: any) => /^\d{4}-\d{2}-\d{2}T/.test(c.cryptoProperties.certificateProperties.notValidAfter)));
  const protocols = byType("protocol");
  assert.equal(protocols.length, 3); // nginx protocols + nginx ciphers + sshd kex
  const types = protocols.map((c: any) => c.cryptoProperties.protocolProperties.type).sort();
  assert.deepEqual(types, ["ssh", "tls", "tls"]);
  const ssh = protocols.find((c: any) => c.cryptoProperties.protocolProperties.type === "ssh");
  assert.equal(ssh.cryptoProperties.protocolProperties.version, "2");
});

test("fixtures: every PEM fixture in fixtures/certs parses (no dead fixtures)", () => {
  for (const f of readdirSync(certsDir).filter((f) => f.endsWith(".pem"))) {
    for (const block of extractPemCertificates(pem(f))) {
      assert.ok(block.der, `${f}: undecodable block`);
      const res = parseCertificate(block.der!);
      assert.ok(res.ok, `${f}: ${!res.ok ? res.reason : ""}`);
    }
  }
});
