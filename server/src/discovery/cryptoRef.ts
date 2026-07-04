import type { CryptoAsset } from "../types.js";

/**
 * CycloneDX 1.6 cryptographic-asset reference data and the quantum-classification
 * policy, kept in one place so the CBOM emitter and the conformance validator
 * share a single source of truth.
 *
 * Every enum below is transcribed from the official CycloneDX 1.6 JSON schema
 * (schema/bom-1.6.schema.json); every OID is taken from an authoritative registry
 * / RFC (citations live in the v2.0 research log). We deliberately emit an OID,
 * curve, or security level ONLY when we can assert it without guessing — for
 * findings that lump two algorithms together (e.g. "DES/3DES", "MD5/SHA-1",
 * "Ed25519/X25519") we withhold the ambiguous field rather than overclaim, which
 * is the right posture for a tool whose output a crypto-literate buyer will audit.
 */

// ---- CycloneDX 1.6 enums (verified against the 1.6 schema) ------------------
export const CDX_PRIMITIVES = [
  "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke",
  "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown",
] as const;

export const CDX_CRYPTO_FUNCTIONS = [
  "generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive",
  "sign", "verify", "encapsulate", "decapsulate", "other", "unknown",
] as const;

export const CDX_EXECUTION_ENVIRONMENTS = [
  "software-plain-ram", "software-encrypted-ram", "software-tee", "hardware",
  "other", "unknown",
] as const;

export const CDX_ASSET_TYPES = [
  "algorithm", "certificate", "protocol", "related-crypto-material",
] as const;

export const CDX_PROTOCOL_TYPES = [
  "tls", "ssh", "ipsec", "ike", "sstp", "wpa", "other", "unknown",
] as const;

type Primitive = (typeof CDX_PRIMITIVES)[number];
type CryptoFunction = (typeof CDX_CRYPTO_FUNCTIONS)[number];

export interface AlgorithmDetails {
  /** CycloneDX algorithmProperties.primitive (single-valued). */
  primitive: Primitive;
  /** algorithmProperties.cryptoFunctions[]. */
  cryptoFunctions: CryptoFunction[];
  /** cryptoProperties.oid — only set when unambiguous. */
  oid?: string;
  /** algorithmProperties.curve — only set when the curve is known. */
  curve?: string;
  /** algorithmProperties.classicalSecurityLevel, in bits, for the typical
   *  parameter set. Omitted when the key size / variant is unknown. */
  classicalSecurityLevel?: number;
}

// Verified algorithm OIDs (registry/RFC citations in the v2.0 research log).
const OID = {
  RSA: "1.2.840.113549.1.1.1", // rsaEncryption — RFC 8017 / PKCS#1
  EC: "1.2.840.10045.2.1", // id-ecPublicKey — RFC 5480 (covers ECDSA & ECDH keys)
  DSA: "1.2.840.10040.4.1", // id-dsa — RFC 3279
  DH: "1.2.840.10046.2.1", // dhpublicnumber (X9.42) — RFC 3279
} as const;

/**
 * Map one discovered asset to its CycloneDX algorithm facts. Keys off `family`
 * (the reliable signal) and refines using the algorithm label only where that is
 * safe. classicalSecurityLevel is emitted ONLY where the detected token itself
 * fixes the strength — a named curve, a keyed cipher size, or a broken hash. For
 * RSA/DSA/DH and unspecified EC curves the scanner observes *use*, not key size,
 * so we omit the level rather than assert a number we never saw.
 */
export function algorithmDetails(a: CryptoAsset): AlgorithmDetails {
  const alg = a.algorithm;
  switch (a.family) {
    case "RSA":
      // Key size (and thus classical strength) is not observed from a usage scan.
      return {
        primitive: "pke",
        cryptoFunctions: ["encrypt", "decrypt", "sign", "verify", "keygen"],
        oid: OID.RSA,
      };
    case "ECC": {
      // Curve25519 patterns lump Ed25519 (signature) with X25519 (key agreement):
      // we can name the curve (which fixes the ~128-bit strength) but not assert
      // one OID, so we omit the OID.
      if (/25519/.test(alg)) {
        return {
          primitive: "signature",
          cryptoFunctions: ["sign", "verify", "keygen"],
          curve: "Curve25519",
          classicalSecurityLevel: 128,
        };
      }
      // ECDH-only label → key agreement; otherwise treat as a signing curve. The
      // specific curve is unknown here, so the strength is left unstated.
      const keyAgreeOnly = /\bECDH\b/.test(alg) && !/ECDSA/.test(alg);
      return keyAgreeOnly
        ? { primitive: "key-agree", cryptoFunctions: ["keygen", "keyderive"], oid: OID.EC }
        : { primitive: "signature", cryptoFunctions: ["sign", "verify", "keygen"], oid: OID.EC };
    }
    case "DSA":
      return { primitive: "signature", cryptoFunctions: ["sign", "verify", "keygen"], oid: OID.DSA };
    case "DH":
      return { primitive: "key-agree", cryptoFunctions: ["keygen", "keyderive"], oid: OID.DH };
    case "Asymmetric":
      // PKCS#8 block whose algorithm can't be read from the header — assert nothing.
      return { primitive: "other", cryptoFunctions: [] };
    case "SymmetricLegacy":
      if (/AES/.test(alg)) {
        return { primitive: "block-cipher", cryptoFunctions: ["encrypt", "decrypt"], classicalSecurityLevel: 128 };
      }
      // "DES/3DES" spans 56-bit DES and ~112-bit 3DES — ambiguous, so no level/OID.
      return { primitive: "block-cipher", cryptoFunctions: ["encrypt", "decrypt"] };
    case "HashLegacy":
      // MD5 and SHA-1 are both collision-broken → 0-bit effective for signatures.
      return { primitive: "hash", cryptoFunctions: ["digest"], classicalSecurityLevel: 0 };
    case "PQC":
      // Only parsed X.509 certificates carry this family; the algorithm label
      // names the exact parameter set (ML-DSA-65, ML-KEM-768, SLH-DSA-…).
      return /ML-KEM/.test(alg)
        ? { primitive: "kem", cryptoFunctions: ["encapsulate", "decapsulate"] }
        : { primitive: "signature", cryptoFunctions: ["sign", "verify"] };
    default:
      return { primitive: "unknown", cryptoFunctions: [] };
  }
}

// ── ENG-02: certificate / protocol asset classification for the CBOM ─────────

/** patternIds whose finding is a TLS or SSH configuration POSTURE, emitted as a
 *  CycloneDX `protocol` asset (not an `algorithm`). */
const PROTOCOL_PATTERNS: Record<string, "tls" | "ssh"> = {
  "tls-legacy-protocol-nginx": "tls",
  "tls-weak-cipher-nginx": "tls",
  "tls-legacy-protocol-apache": "tls",
  "tls-weak-cipher-apache": "tls",
  "tls-legacy-haproxy": "tls",
  "ssh-classical-kex": "ssh",
};

export function protocolTypeFor(a: CryptoAsset): "tls" | "ssh" | null {
  return PROTOCOL_PATTERNS[a.patternId] ?? null;
}

/**
 * Best-effort protocol VERSION from the matched line. Only asserted when the
 * snippet names exactly one legacy version — a directive enabling several
 * (`ssl_protocols TLSv1 TLSv1.1`) gets no single version rather than a guess.
 * SSH posture lines are always protocol 2 (KexAlgorithms exists only there).
 */
export function protocolVersionFor(a: CryptoAsset): string | null {
  const kind = protocolTypeFor(a);
  if (kind === "ssh") return "2";
  if (kind !== "tls") return null;
  const s = a.snippet;
  const found = new Set<string>();
  if (/\bSSLv3\b|force-sslv3/.test(s)) found.add("3.0");
  if (/\bTLSv1(?:\.0)?(?![.\d])/.test(s) || /force-tlsv10/.test(s)) found.add("1.0");
  if (/\bTLSv1\.1(?![.\d])/.test(s) || /force-tlsv11/.test(s)) found.add("1.1");
  return found.size === 1 ? [...found][0] : null;
}

/** Is this asset a parsed or unparseable X.509 certificate finding (ENG-02)? */
export function isCertificateAsset(a: CryptoAsset): boolean {
  return a.patternId === "x509-certificate" || a.patternId === "x509-cert-unparseable";
}

/**
 * ───────────────────────────────────────────────────────────────────────────
 * POLICY SEAM — quantum security category. This function is intentionally the
 * one piece of judgment in the CBOM, and it is the founder's call to own/tune.
 *
 * CycloneDX `nistQuantumSecurityLevel` is NOT a bit count — it is the NIST PQC
 * security strength *category*, an integer 0–6 where:
 *   0 = meets none of the categories (no quantum resistance)
 *   1 = ≥ brute-forcing AES-128   2 = ≥ collision-finding SHA-256
 *   3 = ≥ brute-forcing AES-192   4 = ≥ collision-finding SHA-384
 *   5 = ≥ brute-forcing AES-256
 *
 * The defensible defaults below:
 *   • RSA / ECC / DSA / DH (and unknown asymmetric) → 0. Shor breaks these
 *     outright; key size is irrelevant to quantum resistance.
 *   • MD5 / SHA-1 → 0. Already collision-broken even classically.
 *   • AES-128 → 1. Grover only square-roots symmetric strength (2^128 → ~2^64),
 *     which lands at category 1; AES-256 would be category 5.
 *   • DES / 3DES → 0. Below AES-128 even before Grover.
 *
 * The live debate worth your judgment: do you treat AES-128 as a *passing*
 * category-1 algorithm (Grover is widely considered impractical), or flag it
 * as 0 to push customers to AES-256 (CNSA 2.0's stance)? Change the one line
 * below to encode whichever posture you want the product to take.
 * ───────────────────────────────────────────────────────────────────────────
 */
export function quantumCategory(a: CryptoAsset): number {
  switch (a.family) {
    case "RSA":
    case "ECC":
    case "DSA":
    case "DH":
    case "Asymmetric":
      return 0;
    case "HashLegacy":
      return 0;
    case "SymmetricLegacy":
      return /AES/.test(a.algorithm) ? 1 : 0; // ← AES-128 posture lives here
    case "PQC": {
      // FIPS 203/204/205 claimed categories by parameter set. The algorithm
      // label always names the set (it came from the OID), so the fallback of 1
      // (the weakest passing category) is a floor, never an overclaim.
      const alg = a.algorithm;
      if (/ML-DSA-87|ML-KEM-1024|SLH-DSA-\w+-256/.test(alg)) return 5;
      if (/ML-DSA-65|ML-KEM-768|SLH-DSA-\w+-192/.test(alg)) return 3;
      if (/ML-DSA-44/.test(alg)) return 2;
      return 1;
    }
    default:
      return 0;
  }
}
