import { createHash } from "node:crypto";
import type { CryptoAsset } from "../types.js";
import { VERSION } from "../version.js";
import {
  algorithmDetails,
  quantumCategory,
  quantumExposure,
  isCertificateAsset,
  protocolTypeFor,
  protocolVersionFor,
  CDX_ASSET_TYPES,
  CDX_CRYPTO_FUNCTIONS,
  CDX_EXECUTION_ENVIRONMENTS,
  CDX_PRIMITIVES,
  CDX_PROTOCOL_TYPES,
} from "./cryptoRef.js";

const SPEC_VERSION = "1.6";
// A static source scan cannot observe where the algorithm actually runs (plain
// RAM vs. a TEE/HSM), so we report "unknown" rather than assert an environment
// we never verified — consistent with the tool's no-overclaim posture.
const EXECUTION_ENVIRONMENT = "unknown";
// Fixed namespace so the serial number is a deterministic UUID (v8/SHA-256) of the
// inventory: re-exporting the same findings yields a byte-identical CBOM body.
const QV_NAMESPACE = "1b671a64-40d5-491e-99b0-da01ff1f3341";

export interface CbomMeta {
  target?: string;
  generatedAt?: string;
  toolVersion?: string;
}

/** Deterministic namespaced UUID (RFC 9562 v8 — the "custom" version — over SHA-256
 *  of a fixed namespace + `name`). Was RFC 4122 v5, which is SHA-1 by definition;
 *  moved to SHA-256 so the product itself contains no legacy hash and self-scans
 *  clean. v8 is a valid UUID, and the serial is used only as a stable identifier,
 *  so the algorithm change is transparent to CBOM consumers. */
function deterministicUuid(name: string): string {
  const ns = Buffer.from(QV_NAMESPACE.replace(/-/g, ""), "hex");
  const bytes = createHash("sha256").update(ns).update(name, "utf8").digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x80; // version 8 (custom, RFC 9562)
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122/9562 variant
  const h = bytes.toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

/**
 * Stable, content-addressed bom-ref for a finding. Deliberately derived from the
 * finding's identity (file·line·pattern·algorithm) rather than the volatile
 * per-scan asset id, so the same crypto inventory always produces the same
 * bom-refs and the CBOM diffs cleanly across re-scans.
 */
function bomRef(a: CryptoAsset): string {
  const h = createHash("sha256")
    .update(`${a.file}|${a.line}|${a.patternId}|${a.algorithm}`)
    .digest("hex");
  return `crypto:${h.slice(0, 12)}`;
}

/**
 * Serialize discovered crypto assets to a CycloneDX 1.6 Cryptography Bill of
 * Materials. Each finding becomes a `cryptographic-asset` component carrying its
 * primitive, OID (when unambiguous), crypto functions, classical strength, and
 * NIST quantum-security category, plus a source occurrence. A `dependencies`
 * graph records that the scanned application consumes each discovered algorithm.
 */
export function assetsToCbom(assets: CryptoAsset[], meta: CbomMeta = {}): Record<string, unknown> {
  // Order by bom-ref for deterministic output, and disambiguate the rare case of
  // two identical findings so every bom-ref in the document is unique.
  const sorted = [...assets].sort((x, y) => bomRef(x).localeCompare(bomRef(y)));
  const seen = new Map<string, number>();
  const refOf = new Map<CryptoAsset, string>();
  for (const a of sorted) {
    const base = bomRef(a);
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    refOf.set(a, n === 0 ? base : `${base}#${n}`);
  }

  const components = sorted.map((a) => {
    // Three CycloneDX asset shapes (ENG-02): a parsed/unparseable X.509
    // certificate carries certificateProperties; a TLS/SSH configuration
    // posture finding carries protocolProperties; everything else is an
    // algorithm asset as before. The certificate's key/signature algorithm
    // detail lives in the quantumvault:cert* properties — we do not fabricate a
    // separate algorithm component just to satisfy signatureAlgorithmRef.
    let cryptoProperties: Record<string, unknown>;
    const protocolType = protocolTypeFor(a);
    if (isCertificateAsset(a)) {
      cryptoProperties = {
        assetType: "certificate",
        certificateProperties: {
          ...(a.certSubject != null ? { subjectName: a.certSubject } : {}),
          ...(a.certIssuer != null ? { issuerName: a.certIssuer } : {}),
          ...(a.certNotBefore != null ? { notValidBefore: a.certNotBefore } : {}),
          ...(a.certNotAfter != null ? { notValidAfter: a.certNotAfter } : {}),
          certificateFormat: "X.509",
        },
      };
    } else if (protocolType) {
      const version = protocolVersionFor(a);
      cryptoProperties = {
        assetType: "protocol",
        protocolProperties: {
          type: protocolType,
          ...(version != null ? { version } : {}),
        },
      };
    } else {
      const d = algorithmDetails(a);
      cryptoProperties = {
        assetType: "algorithm",
        ...(d.oid ? { oid: d.oid } : {}),
        algorithmProperties: {
          primitive: d.primitive,
          ...(d.curve ? { curve: d.curve } : {}),
          ...(a.keyBits != null ? { parameterSetIdentifier: String(a.keyBits) } : {}),
          executionEnvironment: EXECUTION_ENVIRONMENT,
          cryptoFunctions: d.cryptoFunctions,
          ...(d.classicalSecurityLevel != null
            ? { classicalSecurityLevel: d.classicalSecurityLevel }
            : {}),
          nistQuantumSecurityLevel: quantumCategory(a),
        },
      };
    }
    return {
      type: "cryptographic-asset",
      "bom-ref": refOf.get(a)!,
      name: a.algorithm,
      cryptoProperties,
      evidence: { occurrences: [{ location: a.file, line: a.line }] },
      properties: [
        { name: "quantumvault:family", value: a.family },
        { name: "quantumvault:patternId", value: a.patternId },
        { name: "quantumvault:confidence", value: a.confidence },
        ...(a.demotionReason ? [{ name: "quantumvault:demotionReason", value: a.demotionReason }] : []),
        { name: "quantumvault:quantumVulnerable", value: String(a.quantumVulnerable) },
        // Honest exposure tier (⚑4): "shor-broken" (RSA/ECC/DSA/DH — broken
        // outright by a CRQC) vs "grover-weakened" (AES-128 — security margin
        // reduced, migrate on the normal upgrade cycle) vs "classically-weak"
        // (DES/3DES/RC4/MD5/SHA-1 — attackable without any quantum computer).
        { name: "quantumvault:quantumExposure", value: quantumExposure(a) },
        { name: "quantumvault:pqcReplacement", value: a.pqcReplacement },
        { name: "quantumvault:remediationStatus", value: a.status },
        ...(a.certKeyAlgorithm ? [{ name: "quantumvault:certKeyAlgorithm", value: a.certKeyAlgorithm }] : []),
        ...(a.certSignatureAlgorithm
          ? [{ name: "quantumvault:certSignatureAlgorithm", value: a.certSignatureAlgorithm }]
          : []),
        ...(a.certExpired != null ? [{ name: "quantumvault:certExpired", value: String(a.certExpired) }] : []),
        ...(a.risk ? [{ name: "quantumvault:riskScore", value: String(a.risk.score) }] : []),
      ],
    };
  });

  const appRef = `application:${meta.target ?? "scan-target"}`;
  const dependsOn = components.map((c) => c["bom-ref"]);
  // Deterministic serial: identity of the inventory, not the moment of export.
  const serial = deterministicUuid(`${meta.target ?? ""}\n${dependsOn.join(",")}`);

  return {
    bomFormat: "CycloneDX",
    specVersion: SPEC_VERSION,
    serialNumber: `urn:uuid:${serial}`,
    version: 1,
    metadata: {
      timestamp: meta.generatedAt ?? new Date().toISOString(),
      tools: {
        components: [
          { type: "application", name: "UniQueS", version: meta.toolVersion ?? VERSION },
        ],
      },
      component: { type: "application", "bom-ref": appRef, name: meta.target ?? "scan-target" },
    },
    components,
    dependencies: [{ ref: appRef, dependsOn }],
  };
}

export interface CbomValidation {
  valid: boolean;
  errors: string[];
}

const inEnum = (allowed: readonly string[], v: unknown): boolean =>
  typeof v === "string" && allowed.includes(v);

/**
 * Structural conformance guard for the CBOM we emit: it checks the invariants
 * our output must hold (format/version, a urn:uuid serial, well-formed
 * cryptographic-asset components whose enum values are valid 1.6 spellings, and a
 * dependency graph whose refs all resolve). It is intentionally a fast, dependency
 * -free regression guard over the subset of CycloneDX 1.6 we use — NOT a full
 * JSON-Schema validation (it does not load bom-1.6.schema.json or reject unknown
 * keys). Full conformance against the official CycloneDX 1.6 schema is proven
 * separately in CI by `__tests__/cbom-schema.test.ts` (ajv, dev-dependency only).
 */
export function validateCbom(doc: unknown): CbomValidation {
  const errors: string[] = [];
  const fail = (m: string) => errors.push(m);
  const bom = (doc ?? {}) as Record<string, any>;

  if (bom.bomFormat !== "CycloneDX") fail('bomFormat must be "CycloneDX"');
  if (bom.specVersion !== SPEC_VERSION) fail(`specVersion must be "${SPEC_VERSION}"`);
  if (!/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(bom.serialNumber ?? ""))
    fail("serialNumber must be a urn:uuid");
  if (!Number.isInteger(bom.version) || bom.version < 1) fail("version must be a positive integer");
  if (!bom.metadata?.timestamp) fail("metadata.timestamp is required");

  const refs = new Set<string>();
  const metaRef = bom.metadata?.component?.["bom-ref"];
  if (typeof metaRef === "string") refs.add(metaRef);

  const components = Array.isArray(bom.components) ? bom.components : [];
  if (!Array.isArray(bom.components)) fail("components must be an array");
  components.forEach((c: any, i: number) => {
    const at = `components[${i}]`;
    if (c?.type !== "cryptographic-asset") fail(`${at}.type must be "cryptographic-asset"`);
    if (typeof c?.["bom-ref"] !== "string") fail(`${at} is missing a bom-ref`);
    else refs.add(c["bom-ref"]);

    const cp = c?.cryptoProperties;
    if (!cp) {
      fail(`${at}.cryptoProperties is required`);
      return;
    }
    if (!inEnum(CDX_ASSET_TYPES, cp.assetType)) fail(`${at}.cryptoProperties.assetType invalid: ${cp.assetType}`);
    if (cp.oid != null && typeof cp.oid !== "string") fail(`${at}.cryptoProperties.oid must be a string`);

    if (cp.assetType === "certificate") {
      // Certificate assets carry certificateProperties (all fields optional in
      // 1.6); validity bounds must be strings when present.
      const certp = cp.certificateProperties ?? {};
      for (const f of ["subjectName", "issuerName", "notValidBefore", "notValidAfter", "certificateFormat"])
        if (certp[f] != null && typeof certp[f] !== "string") fail(`${at} certificateProperties.${f} must be a string`);
      return;
    }
    if (cp.assetType === "protocol") {
      const pp = cp.protocolProperties ?? {};
      if (!inEnum(CDX_PROTOCOL_TYPES, pp.type)) fail(`${at} protocolProperties.type invalid: ${pp.type}`);
      if (pp.version != null && typeof pp.version !== "string") fail(`${at} protocolProperties.version must be a string`);
      return;
    }

    const ap = cp.algorithmProperties ?? {};
    if (!inEnum(CDX_PRIMITIVES, ap.primitive)) fail(`${at} primitive invalid: ${ap.primitive}`);
    if (ap.executionEnvironment != null && !inEnum(CDX_EXECUTION_ENVIRONMENTS, ap.executionEnvironment))
      fail(`${at} executionEnvironment invalid: ${ap.executionEnvironment}`);
    for (const fn of ap.cryptoFunctions ?? [])
      if (!inEnum(CDX_CRYPTO_FUNCTIONS, fn)) fail(`${at} cryptoFunction invalid: ${fn}`);
    const q = ap.nistQuantumSecurityLevel;
    if (!Number.isInteger(q) || q < 0 || q > 6) fail(`${at} nistQuantumSecurityLevel must be an integer 0..6`);
    if (ap.classicalSecurityLevel != null && (!Number.isInteger(ap.classicalSecurityLevel) || ap.classicalSecurityLevel < 0))
      fail(`${at} classicalSecurityLevel must be a non-negative integer`);
  });

  (bom.dependencies ?? []).forEach((dep: any, i: number) => {
    if (typeof dep?.ref !== "string") {
      fail(`dependencies[${i}].ref must be a string`);
      return;
    }
    if (!refs.has(dep.ref)) fail(`dependencies[${i}].ref "${dep.ref}" does not resolve to a component`);
    for (const d of dep.dependsOn ?? [])
      if (!refs.has(d)) fail(`dependencies[${i}].dependsOn "${d}" does not resolve to a component`);
  });

  return { valid: errors.length === 0, errors };
}
