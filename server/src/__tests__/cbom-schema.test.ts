import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import Ajv from "ajv";
import addFormats from "ajv-formats";

import { assetsToCbom } from "../discovery/cbom.js";
import type { CryptoAsset, CryptoFamily, RiskScore } from "../types.js";

/**
 * Conformance test: validate the CBOM we emit against the OFFICIAL CycloneDX 1.6
 * JSON Schema — the belt-and-suspenders check that `validateCbom()` (a fast,
 * dependency-free structural guard) deliberately is not. ajv is a dev dependency,
 * so the shipped runtime stays zero-extra-dependency; conformance is proven in CI.
 *
 * The schemas are bundled under ./schemas (fetched from cyclonedx.org/schema on
 * 2026-06-26) so validation runs fully OFFLINE — no network in CI, consistent
 * with the air-gapped posture. bom-1.6 references spdx + jsf; all three are
 * registered so ajv resolves every $ref locally.
 */
const schemasDir = new URL("./schemas/", import.meta.url);
const loadSchema = (file: string) => JSON.parse(readFileSync(new URL(file, schemasDir), "utf8"));

const ajv = new Ajv({ strict: false, allErrors: true });
addFormats(ajv);
// CycloneDX uses a couple of formats ajv-formats doesn't ship; register them
// permissively so they're recognized (not security-relevant for our output) and
// ajv doesn't emit "unknown format" noise while compiling the schema.
ajv.addFormat("iri-reference", true);
ajv.addFormat("idn-email", true);
ajv.addSchema(loadSchema("spdx.schema.json"));
ajv.addSchema(loadSchema("jsf-0.82.schema.json"));
const validateCyclonedx = ajv.compile(loadSchema("bom-1.6.schema.json"));

function assertConforms(doc: unknown, label: string) {
  const ok = validateCyclonedx(doc);
  assert.ok(
    ok,
    `${label}: emitted CBOM is not CycloneDX 1.6 conformant:\n` +
      ajv.errorsText(validateCyclonedx.errors, { separator: "\n" }),
  );
}

const RISK: RiskScore = {
  score: 72,
  priority: "high",
  factors: { dataSensitivity: 60, retentionExposure: 50, hndlExposure: 80, complianceImpact: 40, businessImpact: 55 },
  recommendation: "Migrate to ML-DSA",
  migrationEffortDays: 12,
};

function asset(p: Partial<CryptoAsset> & { family: CryptoFamily }): CryptoAsset {
  return {
    id: "a", scanId: "s", file: "src/app.ts", line: 1, algorithm: "X", keyBits: null,
    language: "typescript", snippet: "", patternId: "p", quantumVulnerable: true,
    confidence: "high", pqcReplacement: "ML-KEM (Kyber)", status: "open", ...p,
  };
}

test("cbom schema: a representative multi-family inventory conforms to the official CycloneDX 1.6 schema", () => {
  const cbom = assetsToCbom(
    [
      asset({ family: "RSA", algorithm: "RSA", keyBits: 2048, file: "a.ts", line: 3, patternId: "rsa-keygen-openssl", risk: RISK }),
      asset({ family: "ECC", algorithm: "Ed25519/X25519", file: "b.ts", line: 9, patternId: "ecc-ed25519", confidence: "low" }),
      asset({ family: "DH", algorithm: "Diffie-Hellman", file: "c.ts", line: 1, patternId: "dh-keyexchange", confidence: "medium" }),
      asset({ family: "DSA", algorithm: "DSA", file: "d.ts", line: 7, patternId: "dsa-usage" }),
      asset({ family: "HashLegacy", algorithm: "MD5/SHA-1", file: "e.ts", line: 2, patternId: "hash-md5-sha1" }),
      asset({ family: "SymmetricLegacy", algorithm: "AES-128", keyBits: 128, file: "f.ts", line: 4, patternId: "sym-aes128" }),
      asset({ family: "Asymmetric", algorithm: "Private key (PKCS#8, algorithm unspecified)", file: "g.pem", line: 1, patternId: "pkcs8-pem-private-key" }),
      // ENG-02: a parsed X.509 certificate (assetType "certificate")…
      asset({
        family: "RSA", algorithm: "X.509 certificate — RSA-2048, SHA-256 with RSA", keyBits: 2048,
        file: "h.pem", line: 1, patternId: "x509-certificate",
        certSubject: "www.example.com", certIssuer: "Example CA",
        certNotBefore: "2026-01-01T00:00:00Z", certNotAfter: "2036-01-01T00:00:00Z",
        certExpired: false, certKeyAlgorithm: "RSA-2048", certSignatureAlgorithm: "SHA-256 with RSA",
      }),
      // …a post-quantum certificate (SAFE — still valid CBOM inventory)…
      asset({
        family: "PQC", algorithm: "X.509 certificate — ML-DSA-65", quantumVulnerable: false,
        file: "i.pem", line: 1, patternId: "x509-certificate",
        certSubject: "pqc.example.com", certExpired: false,
        certKeyAlgorithm: "ML-DSA-65", certSignatureAlgorithm: "ML-DSA-65",
      }),
      // …an unparseable certificate (surfaced, never dropped)…
      asset({
        family: "Asymmetric", algorithm: "Unparseable certificate — review manually",
        file: "j.der", line: 1, patternId: "x509-cert-unparseable", confidence: "low",
      }),
      // …and TLS/SSH protocol-posture findings (assetType "protocol").
      asset({
        family: "Asymmetric", algorithm: "Legacy TLS protocol (SSLv3/TLS 1.0/1.1)",
        file: "nginx.conf", line: 4, patternId: "tls-legacy-protocol-nginx",
        snippet: "ssl_protocols TLSv1 TLSv1.1;", language: "config",
      }),
      asset({
        family: "DH", algorithm: "Classical SSH key exchange (no PQC hybrid)",
        file: "sshd_config", line: 9, patternId: "ssh-classical-kex",
        snippet: "KexAlgorithms ecdh-sha2-nistp256", language: "config",
      }),
    ],
    { target: "/repo", generatedAt: "2026-01-01T00:00:00.000Z" },
  );
  assertConforms(cbom, "representative inventory");
});

test("cbom schema: an empty inventory still conforms to CycloneDX 1.6", () => {
  assertConforms(assetsToCbom([], { target: "/repo" }), "empty inventory");
});
