import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, extname, join, relative, sep } from "node:path";
import type { CryptoAsset, ScanJob } from "../types.js";
import { PATTERNS, extractKeyBits, resolveConfidence, PEM_HEADER } from "./patterns.js";
import {
  parseCertificate,
  extractPemCertificates,
  certificateAssetFacts,
  X509_PARSED_PATTERN_ID,
  X509_UNPARSEABLE_PATTERN_ID,
  PEM_CERT_BEGIN,
  type ParsedCertificate,
} from "./x509.js";
import {
  C_STYLE,
  HASH_STYLE,
  TRIPLE_QUOTE,
  lexStringSpans,
  isMentionStringAt,
  isDisableDirectiveAt,
  isEnumConstRefAt,
  isCodeTokenAt,
  isInTripleQuoteAt,
  isProseMentionAt,
  hasCryptoContext,
  isAmbiguousMatch,
  isBareSshKeyNameAt,
  isUnquotedPathSlugAt,
  isLocaleResourceFile,
  isTypeReferenceAt,
  isEmptyPemBlockAt,
  isGoImportDeclAt,
  tripleQuoteAt,
  tripleQuoteEnd,
} from "./context.js";

const IGNORE_FILE = ".quantumvaultignore";

// Global-flag clones of each pattern's regex so a line can be scanned for ALL
// occurrences (`matchAll`). A prose mention earlier on a line ("rotating the
// diffie-hellman params; createDiffieHellman(2048)") must not steal the match
// position from a real call later on the same line and wrongly downgrade it.
const GLOBAL_REGEX: Map<string, RegExp> = new Map(
  PATTERNS.map((p) => [
    p.id,
    new RegExp(p.regex.source, p.regex.flags.includes("g") ? p.regex.flags : p.regex.flags + "g"),
  ]),
);

/**
 * Load path-prefix ignore patterns from a `.quantumvaultignore` at the scan
 * root. Lines are repo-relative paths (forward slashes); `#` lines and blanks
 * are skipped. Matching is deliberately prefix-based, NOT glob — a file or
 * directory is excluded only when its relative path equals a pattern or sits
 * under it. That keeps suppression explicit and unable to silently hide
 * findings via a stray wildcard. Used to baseline vendored or already-accepted
 * crypto so CI gating (`--fail-on`) isn't tripped by known exceptions.
 */
function loadIgnorePatterns(target: string): string[] {
  try {
    return readFileSync(join(target, IGNORE_FILE), "utf8")
      .split(/\r?\n/)
      .map((l) => l.trim().replace(/\/+$/, ""))
      .filter((l) => l && !l.startsWith("#"));
  } catch {
    return [];
  }
}

function makeIgnoreMatcher(patterns: string[]): (rel: string) => boolean {
  if (patterns.length === 0) return () => false;
  return (rel: string) => {
    const r = rel.split(sep).join("/");
    return patterns.some((p) => r === p || r.startsWith(p + "/"));
  };
}

const EXT_LANG: Record<string, string> = {
  ".js": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".jsx": "javascript",
  ".py": "python",
  ".go": "go",
  ".java": "java",
  ".cs": "csharp",
  ".c": "c",
  ".h": "c",
  ".cpp": "cpp",
  ".cc": "cpp",
  ".cxx": "cpp",
  ".hpp": "cpp",
  ".hh": "cpp",
  ".rs": "rust",
  ".rb": "ruby",
  ".php": "php",
  ".swift": "swift",
  ".kt": "kotlin",
  ".kts": "kotlin",
  ".scala": "scala",
  ".yaml": "yaml",
  ".yml": "yaml",
  ".json": "json",
  ".conf": "config",
  ".cfg": "config",
  ".ini": "config",
  ".pem": "pem",
  ".crt": "pem",
  ".cer": "pem",
  ".der": "pem",
  ".key": "pem",
  ".env": "config",
  ".tf": "terraform",
};

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  ".claude",
  ".idea",
  ".vscode",
  "dist",
  "build",
  "vendor",
  "__pycache__",
  ".venv",
  "target",
  "coverage",
]);

// Directories whose crypto is not part of a production cryptographic posture —
// tests, examples, samples, fixtures, mocks, demos. Skipped by default so a
// scan's grade reflects SHIPPED code, not test fixtures or sample data. Without
// this, a healthy repo gets graded "F" on its own test inputs — the worst first
// impression a security tool can make. (Applied to directories only.)
const NON_PRODUCTION_DIRS = new Set([
  "test", "tests", "__tests__", "spec", "specs", "__mocks__", "mocks", "mock",
  "e2e", "examples", "example", "samples", "sample", "fixtures", "fixture",
  "__fixtures__", "testdata", "demo", "demos",
]);
const NON_PRODUCTION_PREFIX = /^(sample|example|test|spec|mock|fixture|demo)[-_.]/;
function isNonProductionDir(name: string): boolean {
  const n = name.toLowerCase();
  return NON_PRODUCTION_DIRS.has(n) || NON_PRODUCTION_PREFIX.test(n);
}

const MAX_FILE_BYTES = 2_000_000;
const NULL_BYTE = "\x00";

// Extensions that CLAIM to be a certificate. A text file under one of these
// with no PEM armor is either headerless base64 DER (keytool/config-management
// pipelines emit this) or unrecognizable cert-shaped content — parse or surface,
// never report it clean. (.pem/.key are NOT here: a text .pem/.key without armor
// is handled by the normal pattern path, which knows key material shapes.)
const CERT_EXTS = new Set([".der", ".cer", ".crt"]);

// Well-known SSH key files have NO extension, so they'd be skipped by the
// extension map — but they hold real ssh-rsa/ecdsa key material.
const SSH_KEY_FILES = new Set([
  "authorized_keys", "known_hosts", "id_rsa.pub", "id_dsa.pub", "id_ecdsa.pub", "id_ed25519.pub",
]);

// OpenSSH daemon/client configuration also has NO extension; it carries the
// KexAlgorithms posture line (ENG-02), so it must scan as config.
const SSH_CONFIG_FILES = new Set(["sshd_config", "ssh_config"]);

function languageFor(file: string): string | null {
  const ext = extname(file).toLowerCase();
  if (ext in EXT_LANG) return EXT_LANG[ext];
  if (SSH_KEY_FILES.has(basename(file))) return "config";
  if (SSH_CONFIG_FILES.has(basename(file))) return "config";
  if (file.endsWith("Dockerfile") || file.endsWith(".dockerfile")) return "config";
  return null;
}

function* walk(dir: string, root: string, isIgnored: (rel: string) => boolean): Generator<string> {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of entries) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(dir, name);
    if (isIgnored(relative(root, full))) continue;
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      if (isNonProductionDir(name)) continue; // tests/examples/samples: not production posture
      yield* walk(full, root, isIgnored);
    } else if (st.isFile() && st.size <= MAX_FILE_BYTES) {
      yield full;
    }
  }
}

let assetSeq = 0;
function nextAssetId(): string {
  assetSeq += 1;
  return `asset_${assetSeq.toString(36)}_${Date.now().toString(36)}`;
}

/** A fully parsed X.509 certificate as one enriched, high-confidence asset. A
 *  parsed cert is not a mention — the DER structure IS the artifact. */
function parsedCertAsset(
  cert: ParsedCertificate,
  scanId: string, rel: string, line: number, language: string, snippet: string,
): CryptoAsset {
  const facts = certificateAssetFacts(cert);
  return {
    id: nextAssetId(),
    scanId,
    file: rel,
    line,
    language,
    snippet: snippet.trim().slice(0, 240),
    patternId: X509_PARSED_PATTERN_ID,
    confidence: "high",
    status: "open",
    ...facts,
  };
}

/** Honesty invariant — no silent skips: a certificate-shaped file whose parse
 *  fails surfaces as a low-confidence "review manually" finding (per the
 *  ambiguous-PKCS#8 precedent: quantum-vulnerable, algorithm unasserted). */
function unparseableCertAsset(scanId: string, rel: string, language: string, reason: string): CryptoAsset {
  return {
    id: nextAssetId(),
    scanId,
    file: rel,
    line: 1,
    family: "Asymmetric",
    algorithm: "Unparseable certificate — review manually",
    keyBits: null,
    language,
    snippet: `certificate parse failed: ${reason}`.slice(0, 240),
    patternId: X509_UNPARSEABLE_PATTERN_ID,
    quantumVulnerable: true,
    confidence: "low",
    pqcReplacement:
      "Inspect the certificate manually; re-issue as a hybrid or PQC (ML-DSA) X.509 certificate if classical",
    status: "open",
  };
}

/**
 * Return `content` with comment regions blanked to spaces (newlines preserved, so
 * line/column positions are unchanged). String and template literals are kept
 * intact — a crypto name in a comment is a *mention* and must not fire, but real
 * uses live inside strings (e.g. `getInstance("RSA")`, JWT alg values, PEM blocks),
 * so those stay matchable. This is the cheap, regex-level precision win; semantic
 * (AST) call-site detection is the larger follow-on.
 */
export function maskComments(content: string, language: string): string {
  const lineMarkers: string[] = [];
  if (C_STYLE.has(language)) lineMarkers.push("//");
  if (HASH_STYLE.has(language)) lineMarkers.push("#");
  const blockComments = C_STYLE.has(language);
  const triple = TRIPLE_QUOTE.has(language);
  // INI/config files use a leading `;` for comments. Scoped to `language === "config"`
  // (and to line-leading position) so a `;` statement-separator in code, or a `;`
  // inside a config value, is never mistaken for a comment.
  const iniSemicolon = language === "config";
  if (lineMarkers.length === 0 && !blockComments && !triple && !iniSemicolon) return content;

  let out = "";
  let inBlock = false;
  let quote = "";
  for (let k = 0; k < content.length; k++) {
    const ch = content[k];
    if (inBlock) {
      if (ch === "*" && content[k + 1] === "/") { out += "  "; k++; inBlock = false; }
      else out += ch === "\n" ? "\n" : " ";
      continue;
    }
    if (quote) {
      if (ch === "\\") { out += ch + (content[k + 1] ?? ""); k++; continue; } // escaped char (incl. line continuation)
      // A `'` or `"` string cannot span a newline in JS/TS — an unterminated one
      // is a misparse (e.g. a quote char inside a regex char-class `/["']/`) or
      // broken code. Reset at the newline so the bad quote state can't leak into
      // later lines and expose their comments to matching. Template literals
      // (backticks) legitimately span lines and are not reset.
      if (ch === "\n" && quote !== "`") { quote = ""; out += "\n"; continue; }
      out += ch;
      if (ch === quote) quote = "";
      continue;
    }
    if (blockComments && ch === "/" && content[k + 1] === "*") { out += "  "; k++; inBlock = true; continue; }
    // Preserve a triple-quoted string verbatim (it's a string, not a comment) so a
    // crypto name inside a docstring still matches and is classified as a mention —
    // and a stray `#`/quote inside it can't be misread as a comment.
    if (triple && tripleQuoteAt(content, k)) {
      const end = tripleQuoteEnd(content, k, ch);
      out += content.slice(k, end);
      k = end - 1;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") { quote = ch; out += ch; continue; }
    const isLineComment =
      lineMarkers.some((m) => content.startsWith(m, k)) ||
      // a leading `;` in an INI/config file: comment only when it's the first
      // non-whitespace on the line (the emitted line so far is blank).
      (iniSemicolon && ch === ";" && out.slice(out.lastIndexOf("\n") + 1).trim() === "");
    if (isLineComment) {
      while (k < content.length && content[k] !== "\n") { out += " "; k++; }
      if (k < content.length) out += "\n";
      continue;
    }
    out += ch;
  }
  return out;
}

export interface ScanResult {
  job: ScanJob;
  assets: CryptoAsset[];
}

/**
 * Scan a directory tree for quantum-vulnerable cryptographic assets.
 * Returns a completed ScanJob plus the assets discovered (without risk scores;
 * those are attached downstream by the risk scoring service).
 */
export function scanDirectory(target: string, scanId: string): ScanResult {
  const startedAt = new Date();
  const start = performance.now();
  const assets: CryptoAsset[] = [];
  let filesScanned = 0;

  const isIgnored = makeIgnoreMatcher(loadIgnorePatterns(target));

  for (const file of walk(target, target, isIgnored)) {
    // Certificate/key-material pre-check for EVERY pem-language extension
    // (.pem/.crt/.cer/.der/.key). Binary DER under any of them — mislabeled
    // exports are common (`openssl x509 -outform DER -out cert.pem`) — would
    // fail the NULL_BYTE text gate and vanish from the inventory. Attempt a
    // DER certificate parse first; a binary file that does NOT parse is still
    // surfaced (unparseable — review manually), never silently skipped.
    const ext = extname(file).toLowerCase();
    if (EXT_LANG[ext] === "pem") {
      const rel = relative(target, file) || file;
      let buf: Buffer;
      try {
        buf = readFileSync(file);
      } catch {
        // Fail closed on read errors too: a permission-denied certificate/key
        // file reported as if it did not exist is a silent false clean.
        filesScanned += 1;
        assets.push(unparseableCertAsset(scanId, rel, "pem", "file unreadable (permission or I/O error)"));
        continue;
      }
      if (buf.includes(0)) {
        filesScanned += 1;
        const res = parseCertificate(buf);
        assets.push(
          res.ok
            ? parsedCertAsset(res.cert, scanId, rel, 1, "der", `binary DER certificate (${res.cert.keyAlgorithm})`)
            : unparseableCertAsset(scanId, rel, "der", res.reason),
        );
        continue;
      }
      // Headerless base64 DER: a text file under a CERTIFICATE extension with
      // no PEM armor holds either a decodable certificate (base64 of the DER,
      // no BEGIN/END markers) or unrecognizable cert-shaped content. Parse or
      // surface — a certificate artifact in a certificate extension must not
      // scan clean just because the armor is missing.
      if (CERT_EXTS.has(ext) && !buf.includes("-----BEGIN")) {
        filesScanned += 1;
        const body = buf.toString("utf8").replace(/\s+/g, "");
        const der = body.length > 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(body) ? Buffer.from(body, "base64") : null;
        const res = der ? parseCertificate(der) : null;
        assets.push(
          res?.ok
            ? parsedCertAsset(res.cert, scanId, rel, 1, "pem", `headerless base64 DER certificate (${res.cert.keyAlgorithm})`)
            : unparseableCertAsset(scanId, rel, "pem", res ? res.reason : "no PEM armor and not base64 DER"),
        );
        continue;
      }
      // Text .pem/.key (any content) and armored .crt/.cer/.der fall through
      // to the normal PEM text path.
    }

    const language = languageFor(file);
    if (!language) continue;
    filesScanned += 1;

    let content: string;
    try {
      content = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    if (content.indexOf(NULL_BYTE) !== -1) continue; // skip binary files

    const rel = relative(target, file) || file;
    // Normalize line endings so a match's column maps cleanly to an absolute
    // offset (used for syntactic-context lookup); CRLF would otherwise drift it.
    const normalized = content.indexOf("\r") === -1 ? content : content.replace(/\r\n?/g, "\n");
    const lines = normalized.split("\n");
    const maskedContent = maskComments(normalized, language);
    const codeLines = maskedContent.split("\n");
    const stringSpans = lexStringSpans(normalized, language);
    // File-scope crypto corroboration: does this file do cryptography anywhere?
    // Ambiguous shapes (a `dh.generate` call, a bare `des3` token, a `.p12`
    // filename) only count as exposure in a file that shows a real crypto signal.
    // Computed on the COMMENT-MASKED view so a crypto *word* in a comment or
    // docstring ("… not a cryptographic call …") can't vouch for the file — only
    // real crypto code/strings corroborate.
    const cryptoContext = hasCryptoContext(maskedContent);
    // An i18n / localization resource catalog holds only UI strings — a crypto name
    // or key-armor header here is placeholder/hint text, never a use or a real key.
    const localeFile = isLocaleResourceFile(rel);
    // Absolute start offset of each line in `normalized`, so `lineStart[i] +
    // matchColumn` locates a match in the file's string/code segment map.
    const lineStart: number[] = new Array(lines.length);
    for (let i = 0, off = 0; i < lines.length; i++) {
      lineStart[i] = off;
      off += lines[i].length + 1;
    }

    // X.509 PEM certificate blocks: parse each block's DER (a chain = one asset
    // per certificate). A parsed cert REPLACES the generic x509-cert-body regex
    // finding on the same header line — one certificate, one asset (the v0.3.7
    // dedupe rule). A block whose parse FAILS keeps the generic regex finding,
    // so a malformed-but-present cert is surfaced, never silently dropped; an
    // EMPTY block stays with the isEmptyPemBlockAt placeholder downgrade.
    const parsedCertLines = new Set<number>();
    if (normalized.includes(PEM_CERT_BEGIN) && !localeFile) {
      for (const block of extractPemCertificates(normalized)) {
        if (!block.der) continue;
        const res = parseCertificate(block.der);
        if (!res.ok) continue;
        parsedCertLines.add(block.line);
        assets.push(
          parsedCertAsset(res.cert, scanId, rel, block.line, language, lines[block.line - 1] ?? ""),
        );
      }
    }

    for (const pattern of PATTERNS) {
      const langOk =
        pattern.languages.includes(language) ||
        pattern.languages.includes("any") ||
        language === "pem";
      if (!langOk) continue;

      for (let i = 0; i < lines.length; i++) {
        // Dedupe: this block's certificate was fully parsed into an enriched
        // asset — the generic header finding would double-count it.
        if (pattern.id === "x509-cert-body" && parsedCertLines.has(i + 1)) continue;
        const line = lines[i];
        const codeLine = codeLines[i] ?? line;
        if (line.length > 1000) continue;
        // Match against the comment-masked view: a crypto name in a comment is a
        // mention, not a use, and must not fire. String literals are preserved.
        // Scan EVERY occurrence on the line (matchAll) and classify each by its
        // syntactic context (ENG-01a): a crypto name in a mention string (label/
        // log/error/doc/URL slug) is not a use, a config key turned off
        // (`"ssh-rsa": false`) is not exposure, and a bare enum-constant read
        // (`= SignatureAlgorithm.DSA`) is a reference, not an operation. A finding
        // is downgraded only if *every* occurrence qualifies — a single real
        // call-site or structured value keeps it as-is.
        const regex = GLOBAL_REGEX.get(pattern.id)!;
        regex.lastIndex = 0;
        let matched = false;
        let mention = true;
        let disabled = true;
        let enumRef = true;
        let docstring = true; // every occurrence sits inside a triple-quoted docstring
        let codeToken = false; // any occurrence is a bare code token (not in a string)
        let ambiguous = true; // every occurrence is an ambiguous shape (needs file crypto context)
        let bareKeyName = true; // every occurrence is a bare ssh key-type NAME (no key bytes)
        let proseMention = true; // every occurrence is a natural-language prose mention (not a path)
        let typeRef = true; // every occurrence is a type-annotation reference, not a use
        let emptyPem = PEM_HEADER.has(pattern.id); // every occurrence is an empty PEM block (no body)
        for (const occ of codeLine.matchAll(regex)) {
          if (occ.index === undefined) continue;
          matched = true;
          const off = lineStart[i] + occ.index;
          const endOff = off + occ[0].length;
          // A prose mention OR an unquoted config path/route slug is a reference,
          // not a use — both downgrade (subject to the never-downgrade rule).
          if (mention && !isMentionStringAt(normalized, stringSpans, off) &&
              !isUnquotedPathSlugAt(normalized, stringSpans, off, endOff, language)) mention = false;
          if (disabled && !isDisableDirectiveAt(normalized, stringSpans, off, endOff)) disabled = false;
          if (enumRef && !isEnumConstRefAt(normalized, off, endOff, occ[0])) enumRef = false;
          if (docstring && !isInTripleQuoteAt(normalized, stringSpans, off)) docstring = false;
          if (!codeToken && isCodeTokenAt(stringSpans, off)) codeToken = true;
          if (ambiguous && !isAmbiguousMatch(pattern.id, occ[0], normalized, endOff)) ambiguous = false;
          if (bareKeyName && !isBareSshKeyNameAt(normalized, endOff)) bareKeyName = false;
          if (proseMention && !isProseMentionAt(normalized, stringSpans, off)) proseMention = false;
          if (typeRef && !isTypeReferenceAt(normalized, off, endOff, language)) typeRef = false;
          if (emptyPem && !isEmptyPemBlockAt(normalized, endOff)) emptyPem = false;
          if (!mention && !disabled && !enumRef && !ambiguous && !typeRef && !emptyPem) break;
        }
        if (!matched) continue;

        // Go-import precision slice: a bare import declaration (`import
        // "crypto/ecdsa"`, or a grouped-block member) is a package dependency
        // reference, not a crypto operation — demoted to the informational tier
        // with a machine-readable reason, never hidden. The import still
        // corroborates the file's call-site findings via hasCryptoContext.
        // Line-level, not per-occurrence: every match on an import line IS the
        // import path. Go only; Python/JS import handling is unchanged.
        // The line must START in code: an import-shaped line INSIDE a backtick
        // raw-string literal (codegen template) is string content, not an import
        // declaration — it stays with the mention machinery, unstamped.
        const importDecl =
          language === "go" &&
          isCodeTokenAt(stringSpans, lineStart[i]) &&
          isGoImportDeclAt(normalized, lineStart[i]);

        assets.push({
          id: nextAssetId(),
          scanId,
          file: rel,
          line: i + 1,
          family: pattern.family,
          algorithm: pattern.algorithm,
          keyBits: extractKeyBits(line, pattern.family),
          language,
          snippet: line.trim().slice(0, 240),
          patternId: pattern.id,
          quantumVulnerable: pattern.quantumVulnerable,
          confidence: resolveConfidence(pattern.id, { mention, disabled, enumRef, codeToken, docstring, ambiguous, cryptoContext, bareKeyName, proseMention, localeFile, typeRef, emptyPem, importDecl }),
          ...(importDecl ? { demotionReason: "import-declaration" } : {}),
          pqcReplacement: pattern.pqcReplacement,
          status: "open",
        });
      }
    }
  }

  const finishedAt = new Date();
  const durationMs = Math.round(performance.now() - start);

  const job: ScanJob = {
    id: scanId,
    target,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    filesScanned,
    durationMs,
    assetCount: assets.length,
    status: "completed",
  };

  return { job, assets };
}
