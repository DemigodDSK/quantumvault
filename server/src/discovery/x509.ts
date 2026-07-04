import type { CryptoFamily } from "../types.js";

/**
 * ENG-02 — X.509 certificate discovery: a minimal, ZERO-DEPENDENCY DER/ASN.1
 * reader plus just enough X.509 structure to answer the questions a quantum
 * migration needs: what key algorithm (and size/curve), what signature
 * algorithm, whose cert, and until when.
 *
 * Deliberately not a general-purpose ASN.1 library. The reader is TOTAL and
 * BOUNDED: every code path returns a typed parse failure instead of throwing,
 * lengths are validated against the buffer, there is no recursion (only fixed-
 * depth field navigation and capped loops), and input size / child counts /
 * OID arity are hard-capped — malformed or adversarial input can neither hang
 * the scanner nor blow the stack. Pure TypeScript, no native/WASM dependency,
 * so the air-gapped single-binary posture is intact.
 */

// ── hard caps: malformed input must terminate quickly, never hang ────────────
const MAX_DER_BYTES = 100_000; // largest realistic single cert (ML-DSA-87 chains stay well under)
const MAX_CHILDREN = 128; // fields in one SEQUENCE/SET (an RDN list is far smaller)
const MAX_OID_COMPONENTS = 32;

interface Tlv {
  /** Full tag byte (class + constructed bit + tag number). */
  tag: number;
  /** Offset of the first content byte. */
  start: number;
  /** Content length in bytes. */
  length: number;
  /** Offset just past the content (start + length). */
  end: number;
}

/** Read one TLV at `offset`; null on any malformed/truncated encoding. */
function readTlv(buf: Uint8Array, offset: number): Tlv | null {
  if (offset + 2 > buf.length) return null;
  const tag = buf[offset];
  if ((tag & 0x1f) === 0x1f) return null; // high-tag-number form: not used in X.509
  let p = offset + 1;
  const first = buf[p];
  p += 1;
  let length: number;
  if (first < 0x80) {
    length = first; // short form
  } else if (first === 0x80) {
    return null; // indefinite length: BER, not DER
  } else {
    const n = first & 0x7f;
    if (n > 4 || p + n > buf.length) return null; // >4 length bytes cannot be a real cert
    length = 0;
    for (let i = 0; i < n; i++) length = length * 256 + buf[p + i];
    p += n;
  }
  if (length > buf.length - p) return null; // content overruns the buffer
  return { tag, start: p, length, end: p + length };
}

/** Children of a constructed TLV, in order; null if any child is malformed. */
function readChildren(buf: Uint8Array, parent: Tlv): Tlv[] | null {
  const out: Tlv[] = [];
  let p = parent.start;
  while (p < parent.end) {
    const child = readTlv(buf, p);
    if (!child || child.end > parent.end) return null;
    out.push(child);
    if (out.length > MAX_CHILDREN) return null;
    p = child.end;
  }
  return out;
}

/** Decode an OBJECT IDENTIFIER's content bytes to dotted-decimal; null if malformed. */
function decodeOid(buf: Uint8Array, tlv: Tlv): string | null {
  if (tlv.tag !== 0x06 || tlv.length === 0) return null;
  const parts: number[] = [];
  let value = 0;
  for (let i = tlv.start; i < tlv.end; i++) {
    const b = buf[i];
    value = value * 128 + (b & 0x7f);
    if (value > 0xffffffff) return null; // absurd component: not a real OID
    if ((b & 0x80) === 0) {
      if (parts.length === 0) {
        parts.push(Math.min(2, Math.floor(value / 40)), value - Math.min(2, Math.floor(value / 40)) * 40);
      } else {
        parts.push(value);
      }
      value = 0;
      if (parts.length > MAX_OID_COMPONENTS) return null;
    }
  }
  if ((buf[tlv.end - 1] & 0x80) !== 0) return null; // dangling continuation bit
  return parts.join(".");
}

// ── algorithm OID vocabulary (detection reference data, not crypto usage) ────

/** SubjectPublicKeyInfo algorithm OIDs. */
const KEY_OIDS: Record<string, { name: string; family: CryptoFamily }> = {
  "1.2.840.113549.1.1.1": { name: "RSA", family: "RSA" },
  "1.2.840.113549.1.1.10": { name: "RSA-PSS", family: "RSA" }, // RSASSA-PSS key
  "1.2.840.10045.2.1": { name: "ECDSA/ECDH", family: "ECC" }, // id-ecPublicKey; curve in params
  "1.2.840.10040.4.1": { name: "DSA", family: "DSA" },
  "1.2.840.10046.2.1": { name: "Diffie-Hellman", family: "DH" }, // dhpublicnumber (X9.42)
  "1.3.101.110": { name: "X25519", family: "ECC" },
  "1.3.101.111": { name: "X448", family: "ECC" },
  "1.3.101.112": { name: "Ed25519", family: "ECC" },
  "1.3.101.113": { name: "Ed448", family: "ECC" },
  // NIST CSOR post-quantum key algorithms — a cert carrying one of these keys is SAFE.
  "2.16.840.1.101.3.4.3.17": { name: "ML-DSA-44", family: "PQC" },
  "2.16.840.1.101.3.4.3.18": { name: "ML-DSA-65", family: "PQC" },
  "2.16.840.1.101.3.4.3.19": { name: "ML-DSA-87", family: "PQC" },
  "2.16.840.1.101.3.4.4.1": { name: "ML-KEM-512", family: "PQC" },
  "2.16.840.1.101.3.4.4.2": { name: "ML-KEM-768", family: "PQC" },
  "2.16.840.1.101.3.4.4.3": { name: "ML-KEM-1024", family: "PQC" },
};

/** SLH-DSA (FIPS 205) family — NIST CSOR 2.16.840.1.101.3.4.3.20 … .31. */
const SLH_DSA_VARIANTS: Record<string, string> = {
  "20": "SLH-DSA-SHA2-128s", "21": "SLH-DSA-SHA2-128f",
  "22": "SLH-DSA-SHA2-192s", "23": "SLH-DSA-SHA2-192f",
  "24": "SLH-DSA-SHA2-256s", "25": "SLH-DSA-SHA2-256f",
  "26": "SLH-DSA-SHAKE-128s", "27": "SLH-DSA-SHAKE-128f",
  "28": "SLH-DSA-SHAKE-192s", "29": "SLH-DSA-SHAKE-192f",
  "30": "SLH-DSA-SHAKE-256s", "31": "SLH-DSA-SHAKE-256f",
};

function slhDsaName(oid: string): string | null {
  const m = oid.match(/^2\.16\.840\.1\.101\.3\.4\.3\.(\d+)$/);
  if (!m) return null;
  return SLH_DSA_VARIANTS[m[1]] ?? null;
}

/** Signature algorithm OIDs → human name + whether Shor breaks them. */
const SIG_OIDS: Record<string, { name: string; quantumVulnerable: boolean }> = {
  "1.2.840.113549.1.1.4": { name: "MD5 with RSA", quantumVulnerable: true },
  "1.2.840.113549.1.1.5": { name: "SHA-1 with RSA", quantumVulnerable: true },
  "1.2.840.113549.1.1.11": { name: "SHA-256 with RSA", quantumVulnerable: true },
  "1.2.840.113549.1.1.12": { name: "SHA-384 with RSA", quantumVulnerable: true },
  "1.2.840.113549.1.1.13": { name: "SHA-512 with RSA", quantumVulnerable: true },
  "1.2.840.113549.1.1.14": { name: "SHA-224 with RSA", quantumVulnerable: true },
  // RSA-PSS: the hash lives in the AlgorithmIdentifier params (handled below).
  "1.2.840.113549.1.1.10": { name: "RSA-PSS", quantumVulnerable: true },
  "1.2.840.10045.4.1": { name: "ECDSA with SHA-1", quantumVulnerable: true },
  "1.2.840.10045.4.3.1": { name: "ECDSA with SHA-224", quantumVulnerable: true },
  "1.2.840.10045.4.3.2": { name: "ECDSA with SHA-256", quantumVulnerable: true },
  "1.2.840.10045.4.3.3": { name: "ECDSA with SHA-384", quantumVulnerable: true },
  "1.2.840.10045.4.3.4": { name: "ECDSA with SHA-512", quantumVulnerable: true },
  "1.2.840.10040.4.3": { name: "DSA with SHA-1", quantumVulnerable: true },
  "2.16.840.1.101.3.4.3.1": { name: "DSA with SHA-224", quantumVulnerable: true },
  "2.16.840.1.101.3.4.3.2": { name: "DSA with SHA-256", quantumVulnerable: true },
  "1.3.101.112": { name: "Ed25519", quantumVulnerable: true },
  "1.3.101.113": { name: "Ed448", quantumVulnerable: true },
  "2.16.840.1.101.3.4.3.17": { name: "ML-DSA-44", quantumVulnerable: false },
  "2.16.840.1.101.3.4.3.18": { name: "ML-DSA-65", quantumVulnerable: false },
  "2.16.840.1.101.3.4.3.19": { name: "ML-DSA-87", quantumVulnerable: false },
};

/** EC named-curve OIDs. */
const CURVE_OIDS: Record<string, { name: string; bits: number }> = {
  "1.2.840.10045.3.1.7": { name: "P-256", bits: 256 },
  "1.3.132.0.34": { name: "P-384", bits: 384 },
  "1.3.132.0.35": { name: "P-521", bits: 521 },
  "1.3.132.0.10": { name: "secp256k1", bits: 256 },
  "1.3.132.0.33": { name: "P-224", bits: 224 },
};

/** PSS params hash OIDs (RFC 8017). */
const HASH_OIDS: Record<string, string> = {
  "1.3.14.3.2.26": "SHA-1",
  "2.16.840.1.101.3.4.2.1": "SHA-256",
  "2.16.840.1.101.3.4.2.2": "SHA-384",
  "2.16.840.1.101.3.4.2.3": "SHA-512",
  "2.16.840.1.101.3.4.2.4": "SHA-224",
};

// ── parsed-certificate shape ─────────────────────────────────────────────────

export interface ParsedCertificate {
  /** Key algorithm with parameters, e.g. "RSA-2048", "ECDSA P-256", "Ed25519", "ML-DSA-65". */
  keyAlgorithm: string;
  keyFamily: CryptoFamily;
  keyBits: number | null;
  /** e.g. "SHA-256 with RSA", "ECDSA with SHA-384", "RSA-PSS (SHA-256)", "ML-DSA-65". */
  signatureAlgorithm: string;
  /** True when EITHER the key algorithm OR the signature algorithm is classical asymmetric. */
  quantumVulnerable: boolean;
  subject: string | null;
  issuer: string | null;
  notBefore: string | null; // ISO-8601
  notAfter: string | null; // ISO-8601
  expired: boolean;
}

export type X509ParseResult =
  | { ok: true; cert: ParsedCertificate }
  | { ok: false; reason: string };

const fail = (reason: string): X509ParseResult => ({ ok: false, reason });

/** UTCTime (tag 0x17) / GeneralizedTime (0x18) → ISO-8601 string; null if malformed. */
function decodeTime(buf: Uint8Array, tlv: Tlv): string | null {
  if (tlv.length > 32) return null;
  let s = "";
  for (let i = tlv.start; i < tlv.end; i++) s += String.fromCharCode(buf[i]);
  let m: RegExpMatchArray | null = null;
  let year: number;
  if (tlv.tag === 0x17) {
    m = s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z?$/);
    if (!m) return null;
    const yy = Number(m[1]);
    year = yy >= 50 ? 1900 + yy : 2000 + yy; // RFC 5280 UTCTime pivot
  } else if (tlv.tag === 0x18) {
    m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?Z?$/);
    if (!m) return null;
    year = Number(m[1]);
  } else {
    return null;
  }
  const [mo, d, h, mi] = [m[2], m[3], m[4], m[5]];
  const sec = m[6] ?? "00";
  if (Number(mo) < 1 || Number(mo) > 12 || Number(d) < 1 || Number(d) > 31) return null;
  return `${year.toString().padStart(4, "0")}-${mo}-${d}T${h}:${mi}:${sec}Z`;
}

/** Extract the CN (2.5.4.3) from an X.501 Name; falls back to the first attribute value. */
function decodeNameCn(buf: Uint8Array, name: Tlv): string | null {
  const rdns = readChildren(buf, name);
  if (!rdns) return null;
  let fallback: string | null = null;
  for (const rdn of rdns) {
    if (rdn.tag !== 0x31) continue; // SET
    const atvs = readChildren(buf, rdn);
    if (!atvs) continue;
    for (const atv of atvs) {
      if (atv.tag !== 0x30) continue;
      const kv = readChildren(buf, atv);
      if (!kv || kv.length < 2) continue;
      const oid = decodeOid(buf, kv[0]);
      const v = kv[1];
      // PrintableString / UTF8String / IA5String / T61String — decode as UTF-8.
      if (![0x13, 0x0c, 0x16, 0x14].includes(v.tag) || v.length > 512) continue;
      const text = Buffer.from(buf.subarray(v.start, v.end)).toString("utf8");
      if (oid === "2.5.4.3") return text;
      if (fallback === null) fallback = text;
    }
  }
  return fallback;
}

/** Bit length of a DER INTEGER, minding the leading 0x00 sign byte. */
function integerBitLength(buf: Uint8Array, tlv: Tlv): number | null {
  if (tlv.tag !== 0x02 || tlv.length === 0) return null;
  let p = tlv.start;
  let len = tlv.length;
  while (len > 1 && buf[p] === 0x00) { p += 1; len -= 1; } // strip sign/pad bytes
  const first = buf[p];
  if (first === 0) return 0;
  return (len - 1) * 8 + (32 - Math.clz32(first));
}

/** RSA modulus bits from the SPKI BIT STRING (wraps RSAPublicKey ::= SEQUENCE { n, e }). */
function rsaModulusBits(buf: Uint8Array, bitString: Tlv): number | null {
  if (bitString.tag !== 0x03 || bitString.length < 2) return null;
  // First content byte of a BIT STRING is the unused-bit count.
  const inner = readTlv(buf, bitString.start + 1);
  if (!inner || inner.tag !== 0x30 || inner.end > bitString.end) return null;
  const nums = readChildren(buf, inner);
  if (!nums || nums.length < 1) return null;
  return integerBitLength(buf, nums[0]);
}

/** First INTEGER (the prime p) of DSA/DH domain parameters — the key size. */
function domainParamBits(buf: Uint8Array, params: Tlv | undefined): number | null {
  if (!params || params.tag !== 0x30) return null;
  const ints = readChildren(buf, params);
  if (!ints || ints.length === 0) return null;
  return integerBitLength(buf, ints[0]);
}

/** Human name for a signature AlgorithmIdentifier (OID + optional PSS params). */
function signatureName(buf: Uint8Array, algId: Tlv): { name: string; quantumVulnerable: boolean } | null {
  const parts = readChildren(buf, algId);
  if (!parts || parts.length === 0) return null;
  const oid = decodeOid(buf, parts[0]);
  if (!oid) return null;
  const slh = slhDsaName(oid);
  if (slh) return { name: slh, quantumVulnerable: false };
  const known = SIG_OIDS[oid];
  if (!known) return { name: `unknown algorithm (OID ${oid})`, quantumVulnerable: true }; // fail closed
  if (oid === "1.2.840.113549.1.1.10" && parts.length > 1 && parts[1].tag === 0x30) {
    // RSASSA-PSS-params: hashAlgorithm is [0] EXPLICIT AlgorithmIdentifier (default SHA-1).
    const pss = readChildren(buf, parts[1]);
    let hash = "SHA-1";
    if (pss) {
      for (const f of pss) {
        if (f.tag !== 0xa0) continue;
        const inner = readTlv(buf, f.start);
        if (inner && inner.tag === 0x30 && inner.end <= f.end) {
          const hashParts = readChildren(buf, inner);
          const hOid = hashParts && hashParts.length > 0 ? decodeOid(buf, hashParts[0]) : null;
          if (hOid && HASH_OIDS[hOid]) hash = HASH_OIDS[hOid];
        }
      }
    }
    return { name: `RSA-PSS (${hash})`, quantumVulnerable: true };
  }
  return known;
}

/**
 * Parse a DER-encoded X.509 v1/v3 certificate. Total: returns a typed failure
 * for anything that is not a well-formed certificate — never throws.
 */
export function parseCertificate(der: Uint8Array, now: Date = new Date()): X509ParseResult {
  try {
    if (der.length < 16) return fail("input too short to be a certificate");
    if (der.length > MAX_DER_BYTES) return fail("input exceeds the certificate size cap");

    const outer = readTlv(der, 0);
    if (!outer || outer.tag !== 0x30) return fail("not a DER SEQUENCE");
    if (outer.end !== der.length && der.length - outer.end > 4) return fail("trailing bytes after certificate");
    const certParts = readChildren(der, outer);
    if (!certParts || certParts.length < 3) return fail("certificate must have tbs/sigAlg/sigValue");
    const [tbs, outerSigAlg] = certParts;
    if (tbs.tag !== 0x30 || outerSigAlg.tag !== 0x30) return fail("malformed certificate structure");

    const fields = readChildren(der, tbs);
    if (!fields || fields.length < 6) return fail("tbsCertificate is missing required fields");
    // version is [0] EXPLICIT and optional (absent in v1 certs).
    let i = fields[0].tag === 0xa0 ? 1 : 0;
    const serial = fields[i];
    const issuer = fields[i + 2];
    const validity = fields[i + 3];
    const subject = fields[i + 4];
    const spki = fields[i + 5];
    if (serial?.tag !== 0x02) return fail("serialNumber is not an INTEGER");
    if (validity?.tag !== 0x30 || spki?.tag !== 0x30) return fail("malformed validity or subjectPublicKeyInfo");

    const sig = signatureName(der, outerSigAlg);
    if (!sig) return fail("unreadable signatureAlgorithm");

    // Validity — UTCTime and GeneralizedTime both occur in the wild.
    const times = readChildren(der, validity);
    const notBefore = times && times.length >= 1 ? decodeTime(der, times[0]) : null;
    const notAfter = times && times.length >= 2 ? decodeTime(der, times[1]) : null;
    const expired = notAfter !== null && Date.parse(notAfter) < now.getTime();

    // SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }.
    const spkiParts = readChildren(der, spki);
    if (!spkiParts || spkiParts.length < 2 || spkiParts[0].tag !== 0x30) return fail("malformed subjectPublicKeyInfo");
    const keyAlgParts = readChildren(der, spkiParts[0]);
    if (!keyAlgParts || keyAlgParts.length === 0) return fail("unreadable key AlgorithmIdentifier");
    const keyOid = decodeOid(der, keyAlgParts[0]);
    if (!keyOid) return fail("unreadable key algorithm OID");

    let keyAlgorithm: string;
    let keyFamily: CryptoFamily;
    let keyBits: number | null = null;
    let keyVulnerable: boolean;
    const slhKey = slhDsaName(keyOid);
    const known = slhKey ? { name: slhKey, family: "PQC" as CryptoFamily } : KEY_OIDS[keyOid];
    if (!known) {
      keyAlgorithm = `unknown algorithm (OID ${keyOid})`;
      keyFamily = "Asymmetric";
      keyVulnerable = true; // fail closed: an unrecognized key algorithm is not assumed safe
    } else {
      keyFamily = known.family;
      keyVulnerable = known.family !== "PQC";
      keyAlgorithm = known.name;
      if (keyOid === "1.2.840.113549.1.1.1" || keyOid === "1.2.840.113549.1.1.10") {
        keyBits = rsaModulusBits(der, spkiParts[1]);
        keyAlgorithm = keyBits ? `RSA-${keyBits}` : known.name;
      } else if (keyOid === "1.2.840.10045.2.1") {
        // params carry the named curve OID.
        const curveOid = keyAlgParts.length > 1 ? decodeOid(der, keyAlgParts[1]) : null;
        const curve = curveOid ? CURVE_OIDS[curveOid] : undefined;
        keyBits = curve?.bits ?? null;
        keyAlgorithm = curve ? `ECDSA ${curve.name}` : "ECDSA (unknown curve)";
      } else if (keyOid === "1.3.101.112" || keyOid === "1.3.101.110") {
        keyBits = 256;
      } else if (keyOid === "1.3.101.113" || keyOid === "1.3.101.111") {
        keyBits = 448;
      } else if (keyOid === "1.2.840.10040.4.1" || keyOid === "1.2.840.10046.2.1") {
        keyBits = domainParamBits(der, keyAlgParts[1]);
      }
    }

    return {
      ok: true,
      cert: {
        keyAlgorithm,
        keyFamily,
        keyBits,
        signatureAlgorithm: sig.name,
        // Vulnerable if EITHER side is classical asymmetric — a PQC key signed by a
        // classical CA still has a classical trust chain, and vice versa.
        quantumVulnerable: keyVulnerable || sig.quantumVulnerable,
        subject: subject?.tag === 0x30 ? decodeNameCn(der, subject) : null,
        issuer: issuer?.tag === 0x30 ? decodeNameCn(der, issuer) : null,
        notBefore,
        notAfter,
        expired,
      },
    };
  } catch {
    // Belt and braces on the totality guarantee — no malformed input may throw
    // out of this module.
    return fail("unexpected parse error");
  }
}

// ── PEM extraction ───────────────────────────────────────────────────────────

export interface PemCertBlock {
  /** 1-based line number of the -----BEGIN CERTIFICATE----- header. */
  line: number;
  /** Decoded DER bytes; null when the body is empty or not valid base64. */
  der: Uint8Array | null;
}

/** Exported so the scanner's fast pre-check shares this marker instead of
 *  restating detection vocabulary outside the ignored rule-definition files. */
export const PEM_CERT_BEGIN = "-----BEGIN CERTIFICATE-----";
const PEM_CERT_END = "-----END CERTIFICATE-----";
const MAX_PEM_BLOCKS = 200; // a chain file holds a handful; cap pathological input

/**
 * Extract every `-----BEGIN CERTIFICATE-----` block from text. A chain file
 * yields one block per certificate. The body tolerates the escaped-newline form
 * (`\n` inside a single-line string literal, per the isEmptyPemBlockAt
 * precedent); an empty or non-base64 body yields `der: null` so the caller
 * falls back to the generic PEM-header finding rather than dropping the block.
 */
export function extractPemCertificates(content: string): PemCertBlock[] {
  const blocks: PemCertBlock[] = [];
  let from = 0;
  let line = 1;
  let lineScanPos = 0;
  while (blocks.length < MAX_PEM_BLOCKS) {
    const begin = content.indexOf(PEM_CERT_BEGIN, from);
    if (begin === -1) break;
    const bodyStart = begin + PEM_CERT_BEGIN.length;
    const end = content.indexOf(PEM_CERT_END, bodyStart);
    if (end === -1) break; // no END marker: not a complete block
    for (let k = lineScanPos; k < begin; k++) if (content[k] === "\n") line += 1;
    lineScanPos = begin;
    const body = content
      .slice(bodyStart, end)
      .replace(/\\[nrt]/g, "") // escaped whitespace in single-line string literals
      .replace(/\s+/g, "");
    let der: Uint8Array | null = null;
    if (body.length > 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(body)) {
      der = Buffer.from(body, "base64");
    }
    blocks.push({ line, der });
    from = end + PEM_CERT_END.length;
  }
  return blocks;
}

// ── certificate → asset facts ────────────────────────────────────────────────

/** patternId of an X.509 certificate the parser fully read (replaces the generic
 *  x509-cert-body regex finding for the same block — one certificate, one asset). */
export const X509_PARSED_PATTERN_ID = "x509-certificate";
/** patternId of a certificate-shaped file/block the parser could NOT read. Never
 *  silently dropped: surfaced as a low-confidence "review manually" finding. */
export const X509_UNPARSEABLE_PATTERN_ID = "x509-cert-unparseable";

export interface CertAssetFacts {
  family: CryptoFamily;
  algorithm: string;
  keyBits: number | null;
  quantumVulnerable: boolean;
  pqcReplacement: string;
  certSubject?: string;
  certIssuer?: string;
  certNotBefore?: string;
  certNotAfter?: string;
  certExpired?: boolean;
  certKeyAlgorithm?: string;
  certSignatureAlgorithm?: string;
}

/** Asset-facing facts for a successfully parsed certificate. */
export function certificateAssetFacts(cert: ParsedCertificate): CertAssetFacts {
  const sigPart =
    cert.signatureAlgorithm === cert.keyAlgorithm ? "" : `, ${cert.signatureAlgorithm}`;
  return {
    family: cert.keyFamily,
    algorithm: `X.509 certificate — ${cert.keyAlgorithm}${sigPart}`,
    keyBits: cert.keyBits,
    quantumVulnerable: cert.quantumVulnerable,
    pqcReplacement: cert.quantumVulnerable
      ? "Re-issue as a hybrid or PQC (ML-DSA) X.509 certificate per NIST PQC migration"
      : "None — already post-quantum",
    ...(cert.subject != null ? { certSubject: cert.subject } : {}),
    ...(cert.issuer != null ? { certIssuer: cert.issuer } : {}),
    ...(cert.notBefore != null ? { certNotBefore: cert.notBefore } : {}),
    ...(cert.notAfter != null ? { certNotAfter: cert.notAfter } : {}),
    certExpired: cert.expired,
    certKeyAlgorithm: cert.keyAlgorithm,
    certSignatureAlgorithm: cert.signatureAlgorithm,
  };
}
