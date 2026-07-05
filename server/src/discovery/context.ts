/**
 * Per-occurrence syntactic context for a regex match — the down-payment on
 * ENG-01 (call-site precision).
 *
 * The scanner matches against a comment-masked view of a file, so a match can
 * only land in CODE or inside a STRING literal. This module tells those apart
 * and flags the specific false-positive class the pattern-level confidence model
 * can't see: a crypto name embedded in a PROSE string (a log line, an error
 * message, a doc) rather than a real cryptographic use.
 *
 * Deliberately lexical, not a parser: zero dependencies, language-agnostic, and
 * microsecond-fast — preserving the air-gapped, single-binary posture that is a
 * core selling point. True AST / call-graph analysis (ENG-01b) is a later,
 * customer-pulled step; this captures the bulk of string-mention FPs now without
 * a grammar per language.
 */

/** Languages with C-style comments: line (slash-slash) and block. */
export const C_STYLE = new Set([
  "javascript", "typescript", "c", "cpp", "csharp", "java", "kotlin", "scala", "go", "rust", "swift", "php",
]);
/** Languages whose comments are `#` line. */
export const HASH_STYLE = new Set(["python", "ruby", "yaml", "config", "terraform", "php"]);
/** Languages with triple-quoted string literals that legitimately span newlines
 *  (Python docstrings `"""…"""` / `'''…'''`, Scala/Kotlin raw strings). Without
 *  this, the single-quote tokenizer resets at the first newline and a crypto name
 *  in a docstring is misread as live code instead of a prose mention. */
export const TRIPLE_QUOTE = new Set(["python", "scala", "kotlin"]);

/** Consume a triple-quoted string starting at `k` (where the opening triple is);
 *  returns the index just past the closing triple (or end-of-content). */
export function tripleQuoteEnd(content: string, k: number, q: string): number {
  let j = k + 3;
  while (j < content.length && !(content[j] === q && content[j + 1] === q && content[j + 2] === q)) j++;
  return j < content.length ? j + 3 : content.length;
}
/** Is `content` starting a triple quote (`"""` or `'''`) at index k? */
export function tripleQuoteAt(content: string, k: number): string | null {
  const ch = content[k];
  if ((ch === '"' || ch === "'") && content[k + 1] === ch && content[k + 2] === ch) return ch;
  return null;
}

/**
 * Return the [start, end) offsets of every string-literal span in `content`,
 * sorted and non-overlapping. Spans include the surrounding quotes. Comments are
 * tracked only so a quote *inside* a comment isn't mistaken for a string; comment
 * spans themselves are not returned (the scanner never matches inside a comment —
 * those are masked to spaces before matching).
 *
 * Mirrors the tokenizer in `maskComments` (escapes, block + line comments, single
 * / double / template quotes) so the two stay consistent.
 */
export function lexStringSpans(content: string, language: string): Array<[number, number]> {
  const lineMarkers: string[] = [];
  if (C_STYLE.has(language)) lineMarkers.push("//");
  if (HASH_STYLE.has(language)) lineMarkers.push("#");
  const blockComments = C_STYLE.has(language);

  const triple = TRIPLE_QUOTE.has(language);
  const spans: Array<[number, number]> = [];
  let inBlock = false;
  let quote = "";
  let quoteStart = -1;

  for (let k = 0; k < content.length; k++) {
    const ch = content[k];
    if (inBlock) {
      if (ch === "*" && content[k + 1] === "/") { k++; inBlock = false; }
      continue;
    }
    if (quote) {
      if (ch === "\\") { k++; continue; }          // skip the escaped character
      // A `'`/`"` literal can't span a newline (an unterminated one is a misparse,
      // e.g. a quote inside a regex char-class `/["']/`); reset so a bogus span
      // never swallows later lines. Backticks legitimately span lines.
      if (ch === "\n" && quote !== "`") { quote = ""; continue; }
      if (ch === quote) { spans.push([quoteStart, k + 1]); quote = ""; }
      continue;
    }
    if (blockComments && ch === "/" && content[k + 1] === "*") { k++; inBlock = true; continue; }
    // Triple-quoted (multi-line) string: a Python docstring etc. The whole block
    // is one span so a crypto name inside it is classified as a prose mention.
    if (triple && tripleQuoteAt(content, k)) {
      const end = tripleQuoteEnd(content, k, ch);
      spans.push([k, end]);
      k = end - 1;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") { quote = ch; quoteStart = k; continue; }
    if (lineMarkers.some((m) => content.startsWith(m, k))) {
      while (k < content.length && content[k] !== "\n") k++; // skip to end of line
    }
  }
  // An unterminated string (no closing quote) yields no span — it can't be
  // classified as prose, so it falls through to CODE context, which is safe.
  return spans;
}

// A natural-language word: starts with a letter, then ≥2 lowercase letters, all
// alphabetic (no digits, hyphens, or slashes). "weak", "disabled", "handshake",
// "failed", "rejected", "migrating" match; crypto tokens do NOT — "RSA"/"AES" (no
// lowercase tail), "3DES"/"AES128" (digits), "ssh-rsa"/"des-ede3-cbc"/"RSA-OAEP"
// (hyphens), "ECDHE-RSA-AES128-GCM-SHA256" (caps + hyphens + digits).
const NL_WORD = /^[A-Za-z][a-z]{2,}$/;

/**
 * Does a string literal's inner text read like a natural-language LABEL, log line,
 * error, or sentence — rather than a structured crypto value or a tight algorithm
 * identifier? A string is a mention if it has ≥2 whitespace-separated words AND at
 * least one is a natural-language word.
 *
 * This separates a mention ("3DES weak", "Diffie-Hellman handshake failed", "we
 * removed diffie-hellman and 3DES") from a structured value that must keep its
 * confidence: an SSH key line ("ssh-rsa AAAA… user@host"), an OpenSSL cipher list
 * ("ECDHE-RSA-AES128-GCM-SHA256 …"), or a single tight token ("RSA-OAEP",
 * "diffie-hellman", "des-ede3-cbc") — none of which carry a natural-language word.
 * The ≥2-word floor keeps a lone lowercase algorithm token from being downgraded.
 */
function looksLikeMention(inner: string): boolean {
  const words = inner.trim().split(/\s+/);
  if (words.length < 2) return false;
  return words.some((w) => NL_WORD.test(w));
}

/**
 * Does a string literal read like a URL or an absolute path/route, where the
 * crypto name is a path *slug* rather than a cryptographic value? A REST route
 * (`/api/v2/diffie-hellman/rotate`) or a URL (`https://host/v2/ecdsa/sign`)
 * names an endpoint; it is not a use of the primitive.
 *
 * Deliberately narrow to avoid two recall traps the worklist flagged:
 *  - A Go module import is a string too (`"crypto/rsa"`), but it has NO leading
 *    slash and NO scheme — so it is NOT downgraded and a real Go crypto import
 *    still fires.
 *  - A cipher list (`ECDHE-RSA-AES128-GCM-SHA256 …`) carries whitespace and no
 *    leading slash, so it is untouched.
 * The rule covers three path/URL shapes (all whitespace-free): a URL is any
 * string containing `://`; a POSIX path/route starts with `/` (a route slug
 * `/diffie-hellman`, a hierarchy `/api/v2/dh/rotate`, a scheme-relative host
 * `//svc/dh`); a Windows path starts with a drive letter (`C:\…`, `C:/…`). A
 * non-KEY_MATERIAL crypto name is never a *use* inside such a string — uses are
 * code call-sites — so these signals are safe for recall, and key material stays
 * protected by the never-downgrade rule this folds into.
 */
function looksLikePathOrUrl(inner: string): boolean {
  const t = inner.trim();
  if (t.length < 2 || /\s/.test(t)) return false; // routes/URLs carry no whitespace
  if (t.includes("://")) return true; // any scheme://… URL
  if (t[0] === "/") return true; // POSIX absolute path or route slug
  return /^[A-Za-z]:[\\/]/.test(t); // Windows drive path (C:\… or C:/…)
}

/**
 * Is the match at `offset` sitting inside a MENTION string literal — a label, log
 * line, error message, or sentence that merely names a primitive, rather than a
 * structured crypto value or a tight algorithm identifier? A mention is downgraded
 * to a possible-mention; a value keeps its confidence.
 *
 * A template literal containing an interpolation (`${…}`) is never a mention: it
 * embeds executable code, and a real crypto call can live inside the `${…}` — so
 * downgrading it would be a recall loss. A match outside any string literal is
 * CODE context and returns false (left to the pattern's base confidence).
 */
export function isMentionStringAt(content: string, spans: Array<[number, number]>, offset: number): boolean {
  let lo = 0;
  let hi = spans.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [s, e] = spans[mid];
    if (offset < s) hi = mid - 1;
    else if (offset >= e) lo = mid + 1;
    else {
      const literal = content.slice(s, e);
      if (literal.charCodeAt(0) === 96 /* backtick */ && literal.includes("${")) return false;
      const inner = content.slice(s + 1, e - 1); // strip the quotes
      return looksLikeMention(inner) || looksLikePathOrUrl(inner);
    }
  }
  return false;
}

/**
 * Is the match at `offset` inside a natural-language PROSE mention string (a log
 * line, error, label, sentence) — as opposed to a URL/route path slug? This is the
 * prose-only half of `isMentionStringAt`, used to scope the bare-ssh-key-name yield
 * so it fires for a key-type name in prose ("redacted an ssh-rsa entry") but NOT for
 * a name in a path (`/keys/ssh-rsa/import`), which is a deliberate never-downgrade.
 */
export function isProseMentionAt(content: string, spans: Array<[number, number]>, offset: number): boolean {
  let lo = 0;
  let hi = spans.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [s, e] = spans[mid];
    if (offset < s) hi = mid - 1;
    else if (offset >= e) lo = mid + 1;
    else {
      const literal = content.slice(s, e);
      if (literal.charCodeAt(0) === 96 /* backtick */ && literal.includes("${")) return false;
      return looksLikeMention(content.slice(s + 1, e - 1));
    }
  }
  return false;
}

/**
 * Is the match at `offset` a bare CODE token — i.e. NOT inside any string literal?
 * Used to upgrade a JOSE-algorithm identifier (`SignatureAlgorithm RS256 = …`, a
 * real typed declaration) above its conservative base confidence, while a token
 * that only ever appears as a string value (`["RS256"]`, a config list) stays a
 * low-confidence mention.
 */
export function isCodeTokenAt(spans: Array<[number, number]>, offset: number): boolean {
  let lo = 0;
  let hi = spans.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [s, e] = spans[mid];
    if (offset < s) hi = mid - 1;
    else if (offset >= e) lo = mid + 1;
    else return false; // inside a string span
  }
  return true;
}

/**
 * Is the match at `offset` inside a TRIPLE-QUOTED docstring (`"""…"""`/`'''…'''`)?
 * A docstring is unambiguously prose, so even key-material tokens (`ssh-rsa` named
 * as an example in a `:param` doc) are mentions there — unlike an authorized_keys
 * file or config, which is never a docstring. Lets the never-downgrade rule yield
 * for documentation without exposing real key files.
 */
export function isInTripleQuoteAt(content: string, spans: Array<[number, number]>, offset: number): boolean {
  let lo = 0;
  let hi = spans.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [s, e] = spans[mid];
    if (offset < s) hi = mid - 1;
    else if (offset >= e) lo = mid + 1;
    else return tripleQuoteAt(content, s) !== null;
  }
  return false;
}

/** Config values that turn an algorithm OFF. Compared case-insensitively after
 *  stripping surrounding quotes. */
const DISABLE_VALUES = new Set([
  "false", "0", "null", "off", "no", "none", "disabled", "disable", "deny", "denied", "never",
]);

/**
 * Is the match at `[start, end)` a config KEY explicitly assigned a DISABLING
 * value — `"ssh-rsa": false`, `dsa: off`, `weakCiphers = none`? Such a directive
 * turns the algorithm off; counting it as live exposure is backwards (the team
 * did the right thing by disabling it).
 *
 * This is the ONE signal allowed to override the never-downgrade rule for key
 * material: an explicit disable is the strongest possible evidence the primitive
 * is not in use. It is scoped tightly to key position — only a token immediately
 * followed (across an optional closing quote and whitespace) by `:`/`=` then a
 * disabling literal qualifies. A value-position token (`cipher = "ssh-rsa"`, an
 * allow-list array element) is NOT a key, so it still fires; an enabling value
 * (`"ssh-rsa": true`) is not disabling, so it still fires.
 */
export function isDisableDirectiveAt(
  content: string,
  spans: Array<[number, number]>,
  start: number,
  end: number,
): boolean {
  // If the token sits inside a string literal (a quoted JSON/YAML key), the key
  // ends at that span's closing quote; otherwise the key is the bare token.
  let pos = end;
  let lo = 0;
  let hi = spans.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [s, e] = spans[mid];
    if (start < s) hi = mid - 1;
    else if (start >= e) lo = mid + 1;
    else { pos = e; break; } // start is inside this span
  }
  const isSpace = (c: string) => c === " " || c === "\t";
  while (pos < content.length && isSpace(content[pos])) pos++;
  // A C# dictionary-initializer key closes with `]` before the assignment
  // (`["ssh-rsa"] = false`); skip it so the directive is still recognized.
  if (content[pos] === "]") { pos++; while (pos < content.length && isSpace(content[pos])) pos++; }
  if (content[pos] !== ":" && content[pos] !== "=") return false;
  pos++;
  // A PHP/JS arrow assignment (`'ssh-rsa' => false`) has `>` after the `=`.
  if (content[pos] === ">") pos++;
  while (pos < content.length && isSpace(content[pos])) pos++;
  // Read the value token up to the next delimiter, strip quotes, lowercase.
  let j = pos;
  const DELIM = new Set([" ", "\t", "\n", ",", ";", "}", "]", ")"]);
  while (j < content.length && !DELIM.has(content[j])) j++;
  const val = content.slice(pos, j).replace(/^["']+|["']+$/g, "").toLowerCase();
  return DISABLE_VALUES.has(val);
}

// Python typing constructors whose subscript holds TYPES, not values — so a crypto
// class named inside one is a type reference. A plain list/tuple/set literal is NOT
// in this set, so `[RS256, ES256]` (real algorithm constants) is never mistaken for
// a type annotation.
const PY_TYPING_CTOR = /(?:Union|Optional|Type|type|List|Tuple|Dict|Sequence|Iterable|Iterator|Set|FrozenSet|Mapping|MutableMapping|Callable|Annotated|ClassVar|Final|Awaitable|Collection|Container)$/;

/**
 * Is the match a crypto TYPE name used as a type REFERENCE — a return annotation
 * (`-> DSAPrivateKey:`) or a member of a typing subscript (`Union[…, DSAPrivateKey]`,
 * `type[algorithms.AES128]`) — rather than an instantiation or call? It names the
 * type but performs no cryptographic operation: the dominant false-positive class on
 * typed crypto libraries (pyca/cryptography).
 *
 * Scoped to PYTHON, where `->` and typing subscripts are unambiguous. Deliberately
 * does NOT use bare `[`/`,`/`|` (a list literal `[RS256, ES256]` or a Java array
 * initializer `{RS256, ES256}` holds real algorithm CONSTANTS, not types — matching
 * those cost 8 real findings in an earlier, looser version). TS/Java/Go type-ref is
 * left as a tracked gap rather than risk that recall. Signals:
 *  - not immediately followed by `(` (an instantiation `DSAPrivateKey(…)` still fires);
 *  - preceded (after an optional dotted receiver) by `->` — a return annotation; OR
 *  - enclosed in a subscript `Keyword[ … match … ]` whose Keyword is a typing
 *    constructor (Union/Optional/type/List/…), found by a bounded bracket-depth scan.
 */
export function isTypeReferenceAt(content: string, start: number, end: number, language: string): boolean {
  if (language !== "python") return false;
  if (content[end] === "(") return false; // instantiation / call — a real use
  // (a) return annotation: `-> X` (after skipping a dotted receiver like `mod.`)
  let p = start - 1;
  while (p >= 0 && /[\w.$]/.test(content[p])) p--;
  let q = p;
  while (q >= 0 && (content[q] === " " || content[q] === "\t")) q--;
  if (q >= 1 && content[q] === ">" && content[q - 1] === "-") return true;
  // (b) inside a typing subscript: scan left with bracket depth to the enclosing `[`
  // (crossing newlines — pyca's Union[…] annotations are multi-line; the typing
  // keyword before the `[`, not a line boundary, is what proves it's a type).
  let depth = 0;
  const limit = Math.max(0, start - 600);
  for (let i = start - 1; i >= limit; i--) {
    const c = content[i];
    if (c === "]" || c === ")" || c === "}") depth++;
    else if (c === "[") {
      if (depth > 0) { depth--; continue; }
      let j = i - 1; // read the identifier immediately before the enclosing `[`
      while (j >= 0 && (content[j] === " " || content[j] === "\t" || content[j] === "\n")) j--;
      const ke = j + 1;
      while (j >= 0 && /[\w.$]/.test(content[j])) j--;
      return PY_TYPING_CTOR.test(content.slice(j + 1, ke));
    } else if (c === "(" || c === "{") {
      if (depth > 0) depth--; // nested call/dict inside the subscript
      else return false; // a call arg-list / dict / set literal — not a type subscript
    }
  }
  return false;
}

// An enum / class constant read: an identifier, a dot, an ALL-CAPS member
// (`SignatureAlgorithm.DSA`, `Cipher.DES`). Method calls (`dsa.generate`,
// `RSA.Create`) have a lower/Pascal-case member and fail this; bare tokens
// (`DES`, `new DSA`) have no dotted form. The match TEXT must be exactly this
// shape, which is why it isolates the enum-constant arms from every call-site.
const ENUM_CONST_READ = /^[A-Za-z_$][\w$]*\.[A-Z][A-Z0-9_]*$/;

/**
 * Is the match a bare READ of an algorithm enum/class constant — a reference,
 * not an operation? `const x = SignatureAlgorithm.DSA;` and
 * `if (algo == SignatureAlgorithm.DSA)` name DSA but do not sign with it; the
 * actual use would be a keygen/sign call elsewhere. So this occurrence is a
 * possible mention, not exposure.
 *
 * Deliberately narrow — the zero-dependency stand-in for the call-vs-reference
 * data flow a full AST (ENG-01b) would give, scoped so it cannot swallow a real
 * use:
 *  - the match text itself is `Receiver.CONSTANT` (see ENUM_CONST_READ) — this
 *    alone excludes `dsa.generate`, `RSA.Create`, and bare-token matches;
 *  - the next char is neither `(` nor `.` — so an invocation (`X.DSA(…)`) and a
 *    fluent member access (`X.DSA.sign(…)`, where the operation is one `.method`
 *    away) both keep their confidence; and
 *  - it is the RHS of a plain assignment (`lhs = X.DSA`). A comparison
 *    (`== X.DSA`, `!= X.DSA`) is deliberately left at base confidence — it may
 *    guard a real use, so it is too ambiguous to downgrade without data flow. An
 *    argument-position use (`signWith(SignatureAlgorithm.DSA, key)`, preceded by
 *    `(`/`,`) likewise keeps its confidence and still fires.
 *
 * Known limit (the reason a full AST/ENG-01b would do better): this is purely
 * local — it cannot trace a variable, so `const a = SignatureAlgorithm.DSA;` is
 * a possible mention even if `a` is later passed to a signer. That data-flow case
 * is the deliberate trade for staying zero-dependency.
 */
export function isEnumConstRefAt(content: string, start: number, end: number, matchText: string): boolean {
  if (!ENUM_CONST_READ.test(matchText)) return false;
  if (content[end] === "(" || content[end] === ".") return false; // invocation or fluent member access, not a bare read
  let p = start - 1;
  while (p >= 0 && (content[p] === " " || content[p] === "\t")) p--;
  if (p < 0 || content[p] !== "=") return false;
  // Only a plain assignment `=` qualifies; exclude comparison operators that end
  // in `=` (`==` `!=` `<=` `>=`) — those are references that may guard a use.
  const before = content[p - 1];
  return before !== "=" && before !== "!" && before !== "<" && before !== ">";
}

/**
 * FILE-LEVEL crypto corroboration — the file-scope companion to the per-occurrence
 * context above, and the second (file-scope) down-payment on the call-vs-object
 * data flow a full AST (ENG-01b) would give.
 *
 * Some crypto *shapes* are lexically identical whether the receiver / identifier is
 * a real cryptographic object or an ordinary application one: `dh.generate()` reads
 * the same whether `dh` is a DiffieHellman or a DateHelper; `new DSA(zone)` whether
 * DSA is the Digital Signature Algorithm or a "Delivery Service Area"; a bare
 * `des3` / `aes_128` / `md5sum` / `pkcs12` token, or a `report.p12` filename, the
 * same whether it is Triple-DES / AES-128 / a keystore or a mundane business code.
 * At the call site alone they cannot be told apart. But a file that genuinely *does*
 * cryptography carries an unambiguous co-signal — a crypto import, a PEM block, a
 * curve constant, a keygen of a named primitive, a key-size. This scans the whole
 * file once for such signals. An ambiguous shape in a file WITHOUT any is treated as
 * a possible mention (still surfaced for review, not counted as hard exposure) —
 * the honest default. Real crypto files corroborate, so recall is preserved.
 *
 * The signal set is deliberately broad (favouring corroboration) so a real crypto
 * file almost never fails to corroborate — the cost of a false *negative* here is a
 * recall loss, which this project weighs more heavily than an extra possible-mention.
 * It excludes the ambiguous tokens themselves (a bare `dsa`/`rsa`/`dh`/`des3` is NOT
 * a corroborator — that would be circular and let a coincidental variable vouch for
 * its own call).
 */
const CRYPTO_CONTEXT_RE = new RegExp(
  [
    // ── library imports / namespaces / packages ──
    "\\bcrypto\\b", "cryptography", "System\\.Security\\.Cryptography", "javax\\.crypto",
    "java\\.security", "BouncyCastle", "bouncycastle", "libsodium", "\\bsodium\\b", "tweetnacl",
    "node-forge", "forge\\.pki", "CryptoKit", "mbedtls", "wolfssl", "openssl", "OpenSSL::",
    "Crypto\\.(?:PublicKey|Cipher|Hash|Signature)", "\\bpyca\\b", "\\bjose\\b", "jsonwebtoken",
    "jwcrypto", "\\bnimbus", "\\bjjwt\\b",
    // ── unambiguous operations / structured crypto tokens ──
    "createDiffieHellman", "DiffieHellman", "KeyPairGenerator", "MessageDigest",
    "Cipher\\.getInstance", "SecureRandom", "-----BEGIN", "\\bsecp256", "prime256v1",
    "\\bP-(?:256|384|521)\\b", "ssh-rsa\\s+AAAA", "ssh-dss\\s+AAAA", "KeyFactory", "KeyFactorySpi",
    "generatePrivateKey", "\\bx509\\b", "\\bpkcs8\\b", "\\bPrivateKey\\b", "\\bPublicKey\\b",
    "\\bECDSA\\b", "\\bECDH\\b", "\\bEd25519\\b", "\\bX25519\\b", "RSACryptoServiceProvider",
    "RSACng", "DSACryptoServiceProvider", "SignatureAlgorithm", "JWSAlgorithm", "SignedJWT",
    "\\bECDHE\\b", "AES-(?:128|192|256)-(?:CBC|GCM|CTR)", "hashlib", "createHash", "createCipher",
    "\\bHKDF\\b", "\\bPBKDF2\\b", "subtle\\.(?:sign|verify|generateKey|deriveKey|importKey)",
    "modulusLength", "namedCurve", "\\bJWK\\b", "\\bJWS\\b",
  ].join("|"),
  "i",
);

export function hasCryptoContext(content: string): boolean {
  return CRYPTO_CONTEXT_RE.test(content);
}

// A local (line-adjacent) corroborator for the keygen/keyload shapes: a key size, a
// key-size parameter, or an algorithm passed as an argument. Lets an isolated
// `RSA.Create(2048)` / `generateKeyPairSync("rsa", { modulusLength: 2048 })` stay
// actionable even when the file offers no other crypto signal, while a bare
// `RSA.Create(config)` / `orderBook.generateKeyPair(shardCount)` does not.
const LOCAL_KEYISH = /\b(?:512|768|1024|2048|3072|4096|7680|8192|15360)\b|modulusLength|\bbits\b|namedCurve|["'](?:rsa|ec|dsa|secp|prime|ed25519)|\bcurve\b/i;

/**
 * Is this occurrence an inherently-AMBIGUOUS crypto shape — one that resembles a
 * cryptographic operation but is lexically indistinguishable from an ordinary
 * application identifier, and so must be corroborated by file-level crypto context
 * (see `hasCryptoContext`) before it counts as exposure?
 *
 * Scoped per pattern to the specific ambiguous ARM(s) only — the unambiguous arms of
 * the same pattern (`createDiffieHellman`, `DSA_generate`, `des-ede3`, `hashlib.md5`,
 * `pkcs12.Decode(…)`) return false here and keep their base confidence. A trailing
 * window is consulted so a key size / algorithm argument (`LOCAL_KEYISH`) rescues a
 * genuine keygen that happens to share the shape.
 */
export function isAmbiguousMatch(
  patternId: string, matchText: string, content: string, end: number,
): boolean {
  const m = matchText.trim();
  const win = content.slice(end, end + 64); // trailing args: a key size / algorithm token rescues real keygen
  switch (patternId) {
    case "dsa-usage":
      // `dsa.generate(…)` and `new DSA(…)` collide with a DataSourceAdapter / a
      // "Delivery Service Area" class. `DSA_generate`, `ssh-dss`, `DSAPrivateKey`,
      // `SignatureAlgorithm.DSA` are specific and are NOT matched here.
      return /^dsa\.generate$/i.test(m) || (/^new DSA$/.test(m) && !LOCAL_KEYISH.test(win));
    case "dh-keyexchange":
      return /^dh\.generate$/i.test(m); // a DateHelper / DispatchHandler .generate()
    case "rsa-dotnet":
      return /^RSA\.Create$/.test(m) && !LOCAL_KEYISH.test(win); // RSA = "Regional Sales Aggregator" app class
    case "dsa-dotnet":
      return /^DSA\.Create$/.test(m) && !LOCAL_KEYISH.test(win);
    case "sym-des-3des":
      return /^des3$/i.test(m); // "destination hop 3", "detail expansion stage 3" — not Triple-DES
    case "sym-aes128":
      return /^(?:AES128|aes_128)$/i.test(m); // an enum member / location code; `aes-128-cbc` etc. stay
    case "hash-md5-sha1":
      return /^md5sum$/i.test(m); // a non-security cache-key label named `md5sum`
    case "pkcs12-keystore":
      // A real parse/decode CALL (`pkcs12.Decode(data, …)`) keeps confidence; a bare
      // `pkcs12` identifier or a `.p12`/`.pfx` FILENAME string (period-12, page-12,
      // carton-standard-12) is the ambiguous business-code form.
      if (/^pkcs12$/i.test(m)) return !/^\s*\.\s*(?:Decode|decode|Parse|parse|Load|load|Read|read|From|Import|import)/.test(win);
      return true;
    case "rsa-keygen-openssl":
      // `generateKeyPair(…)` is a generic method name (sharding, id allocation).
      // `RSA.generate`, `rsa_generate_key`, `new RSACryptoServiceProvider` are not
      // matched here. A key size / `"rsa"` / `modulusLength` argument rescues it.
      return /generateKeyPair/i.test(m) && !LOCAL_KEYISH.test(win);
    case "ecc-swift-cryptokit":
      return /^P(?:256|384|521)\.(?:Signing|KeyAgreement)$/.test(m); // a "Premium 256" product SKU enum case
    case "jwk-asymmetric-key": {
      // A real JWK carries companion fields — crv/x/y (EC), n/e (RSA), or kid/use/
      // alg/d. A JSON with `"kty":"EC"` but NONE of these is a coincidental
      // descriptor (kty = "kind-type", EC = "Economy Class"), not a key. This is a
      // self-contained shape test, so the field presence — not file context —
      // decides it; a genuine key object keeps its never-downgrade protection.
      const w = content.slice(Math.max(0, end - 200), end + 200);
      return !/"(?:crv|x|y|n|e|d|kid|use|key_ops|alg)"\s*:/.test(w);
    }
    default:
      return false;
  }
}

/** Config/IaC languages where an unquoted scalar value is idiomatic (so a crypto
 *  name can sit in an unquoted path value, invisible to the string-span classifier). */
export const CONFIG_LANG = new Set(["yaml", "config", "terraform", "json"]);

/**
 * Is the PEM header at this match an EMPTY block — a `-----BEGIN …-----` immediately
 * followed by `-----END …-----` with no base64 body between? Such placeholders are
 * used as deliberate negative / error test inputs (surfaced by the step-ca
 * benchmark) and carry no key material, so — unlike a real key block — they are a
 * possible mention, not key material. Requires at least one run of base64 before the
 * END marker to count the block as real.
 */
export function isEmptyPemBlockAt(content: string, end: number): boolean {
  const window = content.slice(end, end + 4000);
  const endIdx = window.search(/-----END/);
  if (endIdx === -1) return false; // END not within the window — a real (large) block, don't assume empty
  // Only whitespace between BEGIN and END => placeholder. Strip escaped whitespace
  // too (`\n`/`\r`/`\t`), so an empty block written as a single Go/JS string literal
  // ("…BEGIN…\n…END…") is recognized as empty just like a multi-line one.
  return window.slice(0, endIdx).replace(/\\[nrt]/g, "").trim() === "";
}

/** Data/resource file extensions that hold only translatable UI strings (not code). */
const LOCALE_DATA_EXT = /\.(?:json|ya?ml|po|pot|properties|arb|xml|strings|resx|ftl)$/i;
/**
 * Is this file an i18n / localization RESOURCE catalog — one whose values are UI
 * strings shown to a user, never code or key material? A crypto name or key-armor
 * header in such a file ("Begins with -----BEGIN PGP PUBLIC KEY BLOCK-----", a
 * placeholder listing "ssh-rsa, ecdsa-sha2-nistp256, …") is hint text, not a
 * cryptographic use — and a real private key never ships inside a translation
 * catalog. So a match here is a possible mention even for key-material patterns.
 *
 * This is the file-scope signal for the i18n false-positive class the real-repo
 * benchmark surfaced (it dominated gitea's FPs, across every non-English locale
 * where the natural-language mention rule — Latin-only — could not recognize the
 * surrounding prose). Scoped to DATA formats in a locale-ish path (or a
 * locale-named file), so a real code module that merely sits in a `locales/` dir is
 * NOT swept — only resource catalogs are.
 */
export function isLocaleResourceFile(rel: string): boolean {
  const p = rel.replace(/\\/g, "/").toLowerCase();
  if (!LOCALE_DATA_EXT.test(p)) return false;
  const base = p.slice(p.lastIndexOf("/") + 1);
  if (/(?:^|\/)(?:locale|locales|_locales|i18n|l10n|lang|langs|translation|translations|messages)\//.test(p)) return true;
  if (/^(?:locale|messages|strings|translation)[._-]/.test(base)) return true;
  if (/\.(?:po|pot|arb|ftl)$/.test(base)) return true; // gettext / Flutter / Fluent catalogs are locale by nature
  if (base === "localizable.strings") return true;
  return false;
}

/**
 * Is the match an ssh key-TYPE NAME (`ssh-rsa`, `ecdsa-sha2-nistp256`) that is NOT
 * followed by actual key BYTES — i.e. a bare name reference rather than a real key
 * line? A genuine SSH public key is `ssh-rsa AAAAB3Nza… user@host`: the name is
 * immediately followed by whitespace and a long base64 blob. A bare name in a log,
 * error, or support hint ("redacted an ssh-rsa entry") has no blob. This lets the
 * mention rule downgrade a key-type NAME in prose while a real key line (blob
 * present) keeps its KEY_MATERIAL never-downgrade protection.
 */
export function isBareSshKeyNameAt(content: string, end: number): boolean {
  return !/^\s+[A-Za-z0-9+/]{20,}/.test(content.slice(end, end + 96));
}

/**
 * Is the match sitting inside an UNQUOTED config value that is a URL or route/path
 * slug — `route: /api/v2/diffie-hellman/rotate`? The quoted form is already a string
 * span and downgraded by `looksLikePathOrUrl`; an unquoted YAML/Terraform value is
 * not a span, so the path classifier never runs on it. Scoped to config/IaC
 * languages and to a token that STARTS with `/` or contains `://` — a bare
 * algorithm value (`keyExchange: diffie-hellman`) is NOT a path and still fires.
 */
export function isUnquotedPathSlugAt(
  content: string,
  spans: Array<[number, number]>,
  start: number,
  end: number,
  language: string,
): boolean {
  if (!CONFIG_LANG.has(language)) return false;
  if (!isCodeTokenAt(spans, start)) return false; // quoted → handled by looksLikePathOrUrl
  const isWS = (c: string | undefined) => c === undefined || c === " " || c === "\t" || c === "\n" || c === "\r";
  let a = start;
  let b = end;
  while (a > 0 && !isWS(content[a - 1])) a--;
  while (b < content.length && !isWS(content[b])) b++;
  const token = content.slice(a, b);
  return token[0] === "/" || token.includes("://");
}

// A single-line Go import: `import "crypto/ecdsa"`, with an optional alias
// (`ecdsakey "crypto/ecdsa"`), blank (`_`), or dot (`.`) name — including the
// one-line grouped form `import ("crypto/ecdsa")`. Quoted with `"` or a raw
// backtick literal (both are legal Go import paths).
const GO_IMPORT_SINGLE = /^import\s+(?:\(\s*)?(?:[A-Za-z_.][\w]*\s+)?["`][^"`]+["`]/;
// A member line INSIDE an `import ( … )` block: optional alias + quoted path,
// then at most a trailing line comment. NO trailing comma — a composite-literal
// element (`"crypto/ecdsa",` in a []string) always carries one in multi-line Go,
// so the comma is the natural discriminator against slice/map literals.
const GO_IMPORT_MEMBER = /^(?:[A-Za-z_.][\w]*\s+)?["`][^"`]+["`]\s*(?:\/\/.*)?$/;
// How many lines to walk back looking for the block opener. Go import blocks sit
// at the top of the file and rarely exceed a few dozen entries; 400 is generous.
const GO_IMPORT_SCAN_LINES = 400;

/**
 * Is the line starting at `lineStartOff` a bare Go IMPORT DECLARATION — a
 * package dependency reference, not a cryptographic operation? Covers the
 * single-line form (`import "crypto/ecdsa"`, aliased / `_` / `.` variants) and
 * a member line of a grouped `import ( … )` block.
 *
 * In Go an unused import does not compile, so the import IS real corroborating
 * evidence that the file operates the package — which is exactly why it is
 * demoted, not dropped: the operation finding is the call-site elsewhere in the
 * file (and the import already corroborates ambiguous shapes file-wide via
 * `hasCryptoContext`). NOTE the 20-repo benchmark's published labels are NOT a
 * blanket "import = FP": an UNcorroborated bare import was labeled FP, while an
 * import whose file shows real call-sites below was labeled TP. This demotion
 * re-tiers BOTH classes to informational (the call-site stays actionable),
 * which shrinks the benchmark's measured actionable set — disclosed in
 * bench/REPORT.md; labels untouched.
 *
 * The grouped-member check walks BACK to the `import (` opener, crossing only
 * lines that are legal inside an import block (members, `//` comments, blanks) —
 * so a bare quoted path in a composite literal or function body never qualifies.
 * Scoped to Go by the caller; a real usage line (`ecdsa.GenerateKey(…)`) or a
 * call whose string argument merely contains the word "import" fails the
 * line-shape tests and keeps its confidence.
 */
export function isGoImportDeclAt(content: string, lineStartOff: number): boolean {
  const nl = content.indexOf("\n", lineStartOff);
  const line = content.slice(lineStartOff, nl === -1 ? content.length : nl).trim();
  if (GO_IMPORT_SINGLE.test(line)) return true;
  if (!GO_IMPORT_MEMBER.test(line)) return false;
  let end = lineStartOff - 1; // offset of the '\n' ending the previous line
  for (let n = 0; n < GO_IMPORT_SCAN_LINES && end >= 0; n++) {
    const prevStart = content.lastIndexOf("\n", end - 1) + 1;
    const prev = content.slice(prevStart, end).trim();
    if (/^import\s*\(/.test(prev)) return true;
    if (prev !== "" && !prev.startsWith("//") && !GO_IMPORT_MEMBER.test(prev)) return false;
    end = prevStart - 1;
  }
  return false;
}
