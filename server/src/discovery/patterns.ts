import type { CryptoPattern, Confidence } from "../types.js";

/**
 * Pattern database for cryptographic asset discovery.
 *
 * Each pattern targets a concrete way quantum-vulnerable cryptography shows up
 * in real source: library calls, key headers, config keys, certificate metadata.
 * Patterns are intentionally specific to keep false positives low while staying
 * language-agnostic where the API surface is shared (e.g. OpenSSL bindings).
 */
export const PATTERNS: CryptoPattern[] = [
  // ---------------------------------------------------------------- RSA
  {
    id: "rsa-keygen-openssl",
    family: "RSA",
    algorithm: "RSA",
    description: "OpenSSL/Node RSA key generation",
    regex: /\b(?:generateKeyPair(?:Sync)?|RSA\.generate|rsa_generate_key|RSA_generate_key|new RSACryptoServiceProvider)\b[\s\S]{0,40}?\b(?:rsa|RSA)?\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    // Java/Kotlin/Scala RSA keygen is covered by rsa-java-keypairgen; excluding
    // them here stops `getInstance("RSA").generateKeyPair()` double-counting.
    languages: ["javascript", "typescript", "python", "go", "csharp", "c"],
    pqcReplacement: "ML-KEM (Kyber) for key exchange, ML-DSA (Dilithium) for signatures",
  },
  {
    id: "rsa-modulus-bits",
    family: "RSA",
    algorithm: "RSA",
    description: "RSA key size declaration (modulus bits)",
    regex: /\b(?:modulusLength|key_size|keySize|rsa_bits|bits)\s*[:=]\s*(512|1024|2048|3072|4096)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["javascript", "typescript", "python", "go", "java", "yaml", "json"],
    pqcReplacement: "ML-KEM (Kyber) / ML-DSA (Dilithium)",
  },
  {
    id: "rsa-pem-header",
    family: "RSA",
    algorithm: "RSA",
    description: "RSA private key PEM block (PKCS#1)",
    // PKCS#1 header is unambiguously RSA. The algorithm-agnostic PKCS#8 header
    // (`BEGIN PRIVATE KEY`, no "RSA") is handled separately so we don't label
    // EC/Ed25519/etc. keys as RSA.
    regex: /-----BEGIN RSA PRIVATE KEY-----/,
    quantumVulnerable: true,
    baseSeverity: "critical",
    languages: ["pem", "config", "any"],
    pqcReplacement: "Re-issue as ML-DSA (Dilithium) signing key",
  },
  {
    id: "pkcs8-pem-private-key",
    family: "Asymmetric",
    algorithm: "Private key (PKCS#8, algorithm unspecified)",
    description: "PKCS#8 private key PEM block — algorithm not determinable from the header",
    regex: /-----BEGIN PRIVATE KEY-----/,
    quantumVulnerable: true,
    baseSeverity: "critical",
    languages: ["pem", "config", "any"],
    pqcReplacement:
      "Identify the key's algorithm and role, then re-issue with the matching NIST PQC scheme (ML-DSA for signing, ML-KEM for key exchange)",
  },
  {
    id: "rsa-python-cryptography",
    family: "RSA",
    algorithm: "RSA",
    description: "Python cryptography/​PyCrypto RSA usage",
    regex: /\b(?:rsa\.generate_private_key|RSA\.generate|PKCS1_OAEP|rsa\.encrypt|rsa\.decrypt)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["python"],
    pqcReplacement: "ML-KEM (Kyber) / ML-DSA (Dilithium)",
  },
  {
    id: "rsa-pgp-private-block",
    family: "RSA",
    algorithm: "RSA (PGP)",
    description: "PGP/GPG private key block (commonly RSA)",
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/,
    quantumVulnerable: true,
    baseSeverity: "critical",
    languages: ["pem", "config", "any"],
    pqcReplacement: "Re-issue PGP identity with ML-DSA (Dilithium) once OpenPGP PQC is finalized",
  },
  {
    id: "rsa-java-keypairgen",
    family: "RSA",
    algorithm: "RSA",
    description: "Java KeyPairGenerator RSA instance",
    regex: /\bKeyPairGenerator\.getInstance\(\s*"RSA"/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["java", "kotlin", "scala"],
    pqcReplacement: "ML-KEM (Kyber) / ML-DSA (Dilithium)",
  },
  {
    id: "rsa-ruby-openssl",
    family: "RSA",
    algorithm: "RSA",
    description: "Ruby OpenSSL RSA key construction",
    regex: /\bOpenSSL::PKey::RSA\.new\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["ruby"],
    pqcReplacement: "ML-KEM (Kyber) / ML-DSA (Dilithium)",
  },
  {
    id: "rsa-php-openssl",
    family: "RSA",
    algorithm: "RSA",
    description: "PHP openssl_pkey_new RSA key generation",
    regex: /\bopenssl_pkey_new\b[\s\S]{0,80}?\bOPENSSL_KEYTYPE_RSA\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["php"],
    pqcReplacement: "ML-KEM (Kyber) / ML-DSA (Dilithium)",
  },
  {
    id: "rsa-rust-crate",
    family: "RSA",
    algorithm: "RSA (rsa crate)",
    description: "Rust rsa crate private-key usage",
    regex: /\bRsaPrivateKey::\w/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["rust"],
    pqcReplacement: "ML-KEM (Kyber) / ML-DSA (Dilithium)",
  },

  // ---------------------------------------------------------------- ECC
  {
    id: "ecc-curve-decl",
    family: "ECC",
    algorithm: "ECDSA/ECDH",
    description: "Elliptic-curve declaration (NIST/secp curves)",
    regex: /\b(?:secp256(?:k1|r1)|secp384r1|secp521r1|prime256v1|P-256|P-384|P-521|ec_genkey|ECDSA|ECDH)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["javascript", "typescript", "python", "go", "java", "csharp", "c", "yaml"],
    pqcReplacement: "ML-KEM (Kyber) for ECDH, ML-DSA / SLH-DSA for ECDSA",
  },
  {
    id: "ecc-ruby-openssl",
    family: "ECC",
    algorithm: "ECDSA/ECDH",
    description: "Ruby OpenSSL elliptic-curve key construction",
    regex: /\bOpenSSL::PKey::EC\.new\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["ruby"],
    pqcReplacement: "ML-KEM (Kyber) for ECDH, ML-DSA / SLH-DSA for ECDSA",
  },
  {
    id: "ecc-ed25519",
    family: "ECC",
    algorithm: "Ed25519/X25519",
    description: "Curve25519 family signature/key exchange",
    regex: /\b(?:ed25519|x25519|curve25519|nacl\.sign|crypto_sign)\b/i,
    quantumVulnerable: true,
    baseSeverity: "medium",
    languages: ["javascript", "typescript", "python", "go", "rust", "c"],
    pqcReplacement: "ML-DSA (Dilithium) signatures, ML-KEM (Kyber) key exchange",
  },

  // ---------------------------------------------------------------- DSA
  {
    id: "dsa-usage",
    family: "DSA",
    algorithm: "DSA",
    description: "Digital Signature Algorithm usage",
    regex: /\b(?:DSA_generate|dsa\.generate|new DSA|ssh-dss|DSAPrivateKey|SignatureAlgorithm\.DSA)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["javascript", "typescript", "python", "go", "java", "config"],
    pqcReplacement: "ML-DSA (Dilithium)",
  },
  {
    id: "dsa-java-keypairgen",
    family: "DSA",
    algorithm: "DSA",
    description: "Java KeyPairGenerator DSA instance",
    regex: /\bKeyPairGenerator\.getInstance\(\s*"DSA"/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["java", "kotlin", "scala"],
    pqcReplacement: "ML-DSA (Dilithium)",
  },
  {
    id: "dsa-ruby-openssl",
    family: "DSA",
    algorithm: "DSA",
    description: "Ruby OpenSSL DSA key construction",
    regex: /\bOpenSSL::PKey::DSA\.new\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["ruby"],
    pqcReplacement: "ML-DSA (Dilithium)",
  },

  // ---------------------------------------------------------------- DH
  {
    id: "dh-keyexchange",
    family: "DH",
    algorithm: "Diffie-Hellman",
    description: "Classical Diffie-Hellman key exchange",
    // The lookbehind excludes a `diffie-hellman-*` token on an OpenSSH
    // KexAlgorithms line — that posture is owned by ssh-classical-kex (ENG-02),
    // and firing both would double-count one line (the v0.3.7 dedupe rule).
    // The {0,1000} bound matches the scanner's 1000-char line gate, so no
    // scannable line can push the token past the lookbehind's reach.
    regex: /\b(?:createDiffieHellman|dh\.generate|DHParameterSpec|(?<!KexAlgorithms[^\n]{0,1000})diffie[-_ ]?hellman)\b/i,
    quantumVulnerable: true,
    baseSeverity: "high",
    // Includes config languages (yaml/json/terraform/conf): a key-exchange config
    // naming `diffie-hellman` is a real DH posture, just like ssh-rsa in IaC. The
    // per-occurrence classifier keeps this honest — a disabled directive
    // (`diffie-hellman: false`), a route/URL slug, a comment, or a prose mention
    // all downgrade to a possible mention; only a live config value stays medium.
    languages: ["javascript", "typescript", "python", "go", "java", "c", "yaml", "json", "config", "terraform"],
    pqcReplacement: "ML-KEM (Kyber)",
  },

  // ---------------------------------------------------------- Symmetric (Grover)
  {
    id: "sym-des-3des",
    family: "SymmetricLegacy",
    algorithm: "DES/3DES",
    description: "DES or Triple-DES symmetric cipher",
    // Bare-token arms keep \b boundaries (so `TripleDESLegacyAdapter` /
    // `TRIPLEDES_DISABLED` don't match); the call-shape arms — `createCipher('des…`
    // and `getInstance("DES")` (Java, surfaced by NIST SARD CWE-327) — carry their
    // own delimiters and must NOT sit inside a trailing \b that a closing quote
    // can never satisfy.
    regex: /\b(?:des-ede3|des3|3des|DESede|Cipher\.DES|TripleDES)\b|createCipher(?:iv)?\(\s*['"]des|getInstance\(\s*"DES"/i,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["javascript", "typescript", "python", "go", "java", "csharp"],
    pqcReplacement: "AES-256 (Grover only halves the security level)",
  },
  {
    id: "sym-aes128",
    family: "SymmetricLegacy",
    algorithm: "AES-128",
    description: "AES-128 (Grover reduces to ~64-bit security)",
    regex: /\b(?:aes-128-(?:cbc|gcm|ctr)|AES128|aes_128)\b/i,
    quantumVulnerable: true,
    baseSeverity: "medium",
    languages: ["javascript", "typescript", "python", "go", "java", "yaml"],
    pqcReplacement: "AES-256-GCM",
  },

  // -------------------------------------------------------------- Hash (Grover)
  {
    id: "hash-md5-sha1",
    family: "HashLegacy",
    algorithm: "MD5/SHA-1",
    description: "Broken/legacy hash function",
    // The call-shape arms end in a quote, so they must NOT sit inside a trailing \b
    // (a `"`→`)` position is never a word boundary — this silently dropped
    // createHash('md5') and MessageDigest.getInstance("MD5") entirely, surfaced by
    // NIST SARD CWE-328). Only the bare `md5sum`/`hashlib` tokens keep boundaries.
    // `SHA-?1` matches both "SHA-1" and Java's "SHA1".
    regex: /createHash\(\s*['"](?:md5|sha1)['"]|\bhashlib\.(?:md5|sha1)\b|MessageDigest\.getInstance\(\s*"(?:MD5|SHA-?1)"|\bmd5sum\b/i,
    quantumVulnerable: true,
    baseSeverity: "medium",
    languages: ["javascript", "typescript", "python", "java"],
    pqcReplacement: "SHA-256 / SHA-3",
  },

  // ------------------------------------------------------------------ TLS / certs
  {
    id: "tls-rsa-cert",
    family: "RSA",
    algorithm: "RSA (X.509)",
    description: "X.509 certificate signed with RSA",
    // RSA must sit IN the signatureAlgorithm value (no comma/newline between), so
    // a PQC line like `signatureAlgorithm: ML-DSA-65, fallback: RSA-PSS` is not
    // mislabeled RSA. The old `ssl_certificate.*\.(crt|pem)` arm was dropped — a
    // cert *path* carries no algorithm, so it flagged PQC certs as RSA.
    regex: /\b(?:sha256WithRSAEncryption|sha1WithRSAEncryption|signatureAlgorithm[^,\n]{0,40}\bRSA)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["config", "nginx", "yaml", "pem"],
    pqcReplacement: "Hybrid X.509 (ML-DSA + classical) per NIST PQC migration",
  },

  // ---------------------------------------------- additional high-confidence
  // Asymmetric private-key PEM blocks (siblings of rsa-pem-header).
  {
    id: "ecc-pem-header",
    family: "ECC",
    algorithm: "ECDSA/ECDH (EC key)",
    description: "Elliptic-curve private key PEM block",
    regex: /-----BEGIN EC PRIVATE KEY-----/,
    quantumVulnerable: true,
    baseSeverity: "critical",
    languages: ["pem", "config", "any"],
    pqcReplacement: "Re-issue as ML-DSA (Dilithium) signing key",
  },
  {
    id: "dsa-pem-header",
    family: "DSA",
    algorithm: "DSA",
    description: "DSA private key PEM block",
    regex: /-----BEGIN DSA PRIVATE KEY-----/,
    quantumVulnerable: true,
    baseSeverity: "critical",
    languages: ["pem", "config", "any"],
    pqcReplacement: "ML-DSA (Dilithium)",
  },
  // OpenSSH-format private key — the DEFAULT `ssh-keygen` output since OpenSSH
  // 7.8 (2018). Wraps an RSA/ECDSA/Ed25519 key; algorithm is in the body, so the
  // family is unspecified-asymmetric. Prime harvest-now-decrypt-later material.
  {
    id: "openssh-pem-private-key",
    family: "Asymmetric",
    algorithm: "OpenSSH private key (algorithm in body)",
    description: "OpenSSH-format private key block",
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----/,
    quantumVulnerable: true,
    baseSeverity: "critical",
    languages: ["pem", "config", "any"],
    pqcReplacement:
      "Identify the wrapped key's algorithm and re-issue with the matching NIST PQC scheme (ML-DSA / ML-KEM)",
  },
  // Encrypted PKCS#8 — sibling of pkcs8-pem-private-key; the `ENCRYPTED` keyword
  // before `PRIVATE KEY` slipped past the plain-PKCS#8 matcher.
  {
    id: "pkcs8-encrypted-pem",
    family: "Asymmetric",
    algorithm: "Encrypted private key (PKCS#8)",
    description: "Encrypted PKCS#8 private key PEM block",
    regex: /-----BEGIN ENCRYPTED PRIVATE KEY-----/,
    quantumVulnerable: true,
    baseSeverity: "critical",
    languages: ["pem", "config", "any"],
    pqcReplacement:
      "Identify the key's algorithm and re-issue with the matching NIST PQC scheme (ML-DSA for signing, ML-KEM for key exchange)",
  },
  // PGP/GPG public key block (commonly RSA/DSA) — a harvestable verification /
  // encryption identity; sibling of rsa-pgp-private-block.
  {
    id: "pgp-public-block",
    family: "Asymmetric",
    algorithm: "PGP public key (algorithm in body)",
    description: "PGP/GPG public key block",
    regex: /-----BEGIN PGP PUBLIC KEY BLOCK-----/,
    quantumVulnerable: true,
    baseSeverity: "medium",
    languages: ["pem", "config", "any"],
    pqcReplacement: "Re-issue the PGP identity with ML-DSA (Dilithium) once OpenPGP PQC is finalized",
  },
  // JWK asymmetric key (`"kty":"RSA"` / `"kty":"EC"`) — concrete key material
  // (modulus/exponent or curve point), common in JWKS endpoints and config.
  {
    id: "jwk-asymmetric-key",
    family: "Asymmetric",
    algorithm: "JWK asymmetric key (RSA/EC)",
    description: "JSON Web Key with an asymmetric key type",
    regex: /"kty"\s*:\s*"(?:RSA|EC)"/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["json", "yaml", "javascript", "typescript", "any"],
    pqcReplacement: "Rotate to a PQC key (ML-DSA / ML-KEM) once JOSE PQC algorithms are standardized",
  },
  // JOSE/JWT signing algorithms imply RSA (RS*/PS*) or ECDSA (ES*) keys.
  // Case-sensitive and bounded so AES256 / arbitrary IDs don't false-match.
  {
    id: "jwt-rsa-alg",
    family: "RSA",
    algorithm: "RSA (JWT RS/PS)",
    description: "JWT/JOSE RSA signing algorithm (RS/PS 256/384/512)",
    regex: /\b(?:RS|PS)(?:256|384|512)\b/,
    quantumVulnerable: true,
    baseSeverity: "medium",
    languages: ["javascript", "typescript", "python", "go", "java", "csharp", "json", "yaml"],
    pqcReplacement: "ML-DSA (Dilithium) signatures",
  },
  {
    id: "jwt-ecdsa-alg",
    family: "ECC",
    algorithm: "ECDSA (JWT ES)",
    description: "JWT/JOSE ECDSA signing algorithm (ES 256/384/512)",
    regex: /\bES(?:256|384|512)\b/,
    quantumVulnerable: true,
    baseSeverity: "medium",
    languages: ["javascript", "typescript", "python", "go", "java", "csharp", "json", "yaml"],
    pqcReplacement: "ML-DSA (Dilithium) signatures",
  },
  // Web Crypto API asymmetric algorithm identifiers.
  {
    id: "rsa-webcrypto",
    family: "RSA",
    algorithm: "RSA (Web Crypto)",
    description: "Web Crypto RSA algorithm identifier",
    regex: /\bRSA-(?:OAEP|PSS)\b|\bRSASSA-PKCS1-v1_5\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["javascript", "typescript"],
    pqcReplacement: "ML-KEM (Kyber) for encryption, ML-DSA (Dilithium) for signatures",
  },
  // SSH public-key key types embedded in IaC / config.
  {
    id: "ssh-rsa-key",
    family: "RSA",
    algorithm: "RSA (SSH)",
    description: "SSH RSA public key type",
    regex: /\bssh-rsa\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["config", "yaml", "terraform", "json", "any"],
    pqcReplacement: "Rotate to a PQC-capable SSH key (ML-DSA) once standardized",
  },
  {
    id: "ssh-ecdsa-key",
    family: "ECC",
    algorithm: "ECDSA (SSH)",
    description: "SSH ECDSA public key type",
    regex: /\becdsa-sha2-nistp(?:256|384|521)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["config", "yaml", "terraform", "json", "any"],
    pqcReplacement: "Rotate to a PQC-capable SSH key (ML-DSA) once standardized",
  },
  // Go standard-library asymmetric crypto.
  {
    id: "go-crypto-rsa",
    family: "RSA",
    algorithm: "RSA (Go crypto)",
    description: "Go crypto/rsa import or key generation",
    regex: /\bcrypto\/rsa\b|\brsa\.GenerateKey\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["go"],
    pqcReplacement: "ML-KEM (Kyber) / ML-DSA (Dilithium)",
  },

  // ---------------------------------------- runtime crypto APIs (.NET/Py/Node/Swift)
  {
    id: "rsa-dotnet",
    family: "RSA",
    algorithm: "RSA (.NET)",
    description: ".NET RSA key construction",
    regex: /\bRSA\.Create\b|\bnew RSACng\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["csharp"],
    pqcReplacement: "ML-KEM (Kyber) / ML-DSA (Dilithium)",
  },
  {
    id: "ecc-dotnet",
    family: "ECC",
    algorithm: "ECDSA (.NET)",
    description: ".NET elliptic-curve key construction",
    regex: /\bECDsa(?:Cng)?\.Create\b|\bnew ECDsaCng\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["csharp"],
    pqcReplacement: "ML-DSA (Dilithium) / SLH-DSA",
  },
  {
    id: "dsa-dotnet",
    family: "DSA",
    algorithm: "DSA (.NET)",
    description: ".NET DSA key construction",
    regex: /\bnew DSACryptoServiceProvider\b|\bDSA\.Create\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["csharp"],
    pqcReplacement: "ML-DSA (Dilithium)",
  },
  {
    id: "ecc-python",
    family: "ECC",
    algorithm: "ECDSA/ECDH (Python)",
    description: "Python cryptography elliptic-curve key generation",
    regex: /\bec\.(?:generate_private_key|derive_private_key)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["python"],
    pqcReplacement: "ML-KEM (Kyber) for ECDH, ML-DSA / SLH-DSA for ECDSA",
  },
  {
    id: "ecc-node-ecdh",
    family: "ECC",
    algorithm: "ECDH (Node)",
    description: "Node.js elliptic-curve Diffie-Hellman",
    regex: /\bcreateECDH\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["javascript", "typescript"],
    pqcReplacement: "ML-KEM (Kyber)",
  },
  {
    id: "ecc-swift-cryptokit",
    family: "ECC",
    algorithm: "ECDSA/ECDH (Swift CryptoKit)",
    description: "Swift CryptoKit NIST-curve usage (P256/P384/P521)",
    regex: /\bP(?:256|384|521)\.(?:Signing|KeyAgreement)\b/,
    quantumVulnerable: true,
    baseSeverity: "medium",
    languages: ["swift"],
    pqcReplacement: "ML-DSA (Dilithium) signatures, ML-KEM (Kyber) key agreement",
  },

  // ----------------------------- embedded C/C++ firmware crypto (mbedTLS,
  // wolfSSL/wolfCrypt, OpenSSL C API). These are the staples of automotive,
  // medical, industrial, and aerospace firmware — long-life devices where
  // RSA/ECC signed today is the canonical harvest-now-decrypt-later target.
  // Patterns are library-prefixed, so false positives stay low.
  {
    id: "rsa-mbedtls",
    family: "RSA",
    algorithm: "RSA (mbedTLS)",
    description: "mbedTLS RSA key or signature usage",
    regex: /\bmbedtls_rsa_(?:init|setup|gen_key|import|complete|pkcs1_encrypt|pkcs1_decrypt|rsassa_pss_sign|rsassa_pkcs1_v15_sign|pkcs1_verify)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["c", "cpp"],
    pqcReplacement: "ML-KEM (Kyber) for key transport, ML-DSA (Dilithium) for signatures",
  },
  {
    id: "ecc-mbedtls",
    family: "ECC",
    algorithm: "ECDSA/ECDH (mbedTLS)",
    description: "mbedTLS elliptic-curve signature or key agreement",
    regex: /\bmbedtls_(?:ecdsa_(?:sign|verify|genkey|init)|ecdh_(?:gen_public|compute_shared|init)|ecp_gen_key(?:pair)?)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["c", "cpp"],
    pqcReplacement: "ML-KEM (Kyber) for ECDH, ML-DSA / SLH-DSA for ECDSA",
  },
  {
    id: "dh-mbedtls",
    family: "DH",
    algorithm: "Diffie-Hellman (mbedTLS)",
    description: "mbedTLS finite-field Diffie-Hellman",
    regex: /\bmbedtls_dhm_(?:init|read_params|make_params|make_public|calc_secret)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["c", "cpp"],
    pqcReplacement: "ML-KEM (Kyber)",
  },
  {
    id: "rsa-wolfssl",
    family: "RSA",
    algorithm: "RSA (wolfCrypt)",
    description: "wolfSSL/wolfCrypt RSA key or signature usage",
    regex: /\bwc_(?:InitRsaKey|MakeRsaKey|RsaPublicEncrypt|RsaPrivateDecrypt|RsaSSL_Sign|RsaSSL_Verify)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["c", "cpp"],
    pqcReplacement: "ML-KEM (Kyber) for key transport, ML-DSA (Dilithium) for signatures",
  },
  {
    id: "ecc-wolfssl",
    family: "ECC",
    algorithm: "ECDSA/ECDH (wolfCrypt)",
    description: "wolfSSL/wolfCrypt elliptic-curve usage",
    regex: /\bwc_ecc_(?:init|make_key|sign_hash|verify_hash|shared_secret)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["c", "cpp"],
    pqcReplacement: "ML-KEM (Kyber) for ECDH, ML-DSA / SLH-DSA for ECDSA",
  },
  {
    id: "rsa-openssl-c",
    family: "RSA",
    algorithm: "RSA (OpenSSL C API)",
    description: "OpenSSL C-API RSA key generation",
    regex: /\b(?:EVP_PKEY_CTX_set_rsa_keygen_bits|EVP_RSA_gen|RSA_generate_key_ex)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["c", "cpp"],
    pqcReplacement: "ML-KEM (Kyber) / ML-DSA (Dilithium)",
  },
  {
    id: "ecc-openssl-c",
    family: "ECC",
    algorithm: "ECDSA/ECDH (OpenSSL C API)",
    description: "OpenSSL C-API elliptic-curve key construction",
    regex: /\b(?:EC_KEY_new_by_curve_name|EC_KEY_generate_key|EVP_EC_gen)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["c", "cpp"],
    pqcReplacement: "ML-KEM (Kyber) for ECDH, ML-DSA / SLH-DSA for ECDSA",
  },
  {
    id: "dh-openssl-c",
    family: "DH",
    algorithm: "Diffie-Hellman (OpenSSL C API)",
    description: "OpenSSL C-API finite-field Diffie-Hellman",
    regex: /\bDH_(?:generate_key|generate_parameters_ex)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["c", "cpp"],
    pqcReplacement: "ML-KEM (Kyber)",
  },

  // ---------------------------------- recall expansion (qbench-confirmed misses)
  // Go elliptic-curve keygen — the EC analogue of go-crypto-rsa, previously
  // invisible (only `crypto/rsa` was covered).
  {
    id: "go-ecdsa",
    family: "ECC",
    algorithm: "ECDSA (Go crypto)",
    description: "Go crypto/ecdsa import or key generation",
    regex: /\bcrypto\/ecdsa\b|\becdsa\.GenerateKey\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["go"],
    pqcReplacement: "ML-DSA (Dilithium) / SLH-DSA",
  },
  // Go DSA keygen — stdlib uses capital-G `GenerateKey`/`GenerateParameters`,
  // which the case-sensitive dsa-usage matcher missed.
  {
    id: "go-dsa",
    family: "DSA",
    algorithm: "DSA (Go crypto)",
    description: "Go crypto/dsa import or key generation",
    regex: /\bcrypto\/dsa\b|\bdsa\.Generate(?:Key|Parameters)\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["go"],
    pqcReplacement: "ML-DSA (Dilithium)",
  },
  // OpenSSL 3.x generic keygen entry point (used for RSA/EC/DSA) — algorithm is
  // set on the context, so the family is unspecified-asymmetric.
  {
    id: "evp-pkey-keygen",
    family: "Asymmetric",
    algorithm: "Asymmetric keygen (OpenSSL EVP_PKEY)",
    description: "OpenSSL EVP_PKEY generic key generation",
    regex: /\bEVP_PKEY_keygen(?:_init)?\b/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["c", "cpp"],
    pqcReplacement: "Identify the algorithm and migrate to ML-KEM (Kyber) / ML-DSA (Dilithium)",
  },
  // Web Crypto elliptic-curve algorithm spec (`name: "ECDSA"` / `"ECDH"`) — a real
  // generateKey call-site; the sibling of rsa-webcrypto, which only covered RSA.
  {
    id: "ecc-webcrypto",
    family: "ECC",
    algorithm: "ECDSA/ECDH (Web Crypto)",
    description: "Web Crypto elliptic-curve algorithm identifier",
    regex: /["']?name["']?\s*:\s*["'](?:ECDSA|ECDH)["']/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["javascript", "typescript", "json"],
    pqcReplacement: "ML-DSA (Dilithium) signatures, ML-KEM (Kyber) key agreement",
  },
  // X.509 certificate body — the DER carries an RSA/ECC public key + signature.
  // Public material, so medium; key material (never downgraded).
  {
    id: "x509-cert-body",
    family: "Asymmetric",
    algorithm: "X.509 certificate (algorithm in body)",
    description: "X.509 certificate PEM block",
    regex: /-----BEGIN CERTIFICATE-----/,
    quantumVulnerable: true,
    baseSeverity: "medium",
    languages: ["pem", "config", "any"],
    pqcReplacement: "Re-issue as a hybrid or PQC (ML-DSA) X.509 certificate per NIST PQC migration",
  },
  // ------------------------------------------------ TLS / SSH posture (ENG-02)
  // Configuration lines that ENABLE a legacy protocol, a weak cipher family, or
  // a classical-only key exchange. Each regex is anchored to its directive so a
  // bare protocol/cipher token elsewhere never fires; disabling forms (`-SSLv3`,
  // `!RC4`, `KexAlgorithms -…`) are remediation and must NOT fire — every arm
  // below has a qbench guard proving the modern/disabled form stays clean.
  {
    id: "tls-legacy-protocol-nginx",
    family: "Asymmetric",
    algorithm: "Legacy TLS protocol (SSLv3/TLS 1.0/1.1)",
    description: "nginx ssl_protocols enabling SSLv3, TLSv1, or TLSv1.1",
    // `TLSv1(?:\.[01])?(?![.\d])` matches TLSv1 / TLSv1.0 / TLSv1.1 but is a
    // dead end on TLSv1.2 / TLSv1.3 (the trailing lookahead rejects the dot).
    regex: /\bssl_protocols\b[^\n]*\b(?:SSLv3|TLSv1(?:\.[01])?)(?![.\d])/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["config", "yaml"],
    pqcReplacement: "TLS 1.3 (hybrid PQC key exchange, e.g. X25519MLKEM768, where supported); TLS 1.2 + ECDHE as the transitional floor",
  },
  {
    id: "tls-weak-cipher-nginx",
    family: "SymmetricLegacy",
    algorithm: "Weak TLS cipher suite (RC4/DES/3DES or static-RSA key exchange)",
    description: "nginx ssl_ciphers enabling RC4, DES/3DES, or TLS_RSA_ (static RSA) suites",
    // A weak token counts only when ENABLED: at a component start (`RC4-SHA`,
    // `:DES-CBC3-SHA`) or mid-cipher-name after a word char (`ECDHE-RSA-RC4-SHA`,
    // via `(?<=\w-)`). OpenSSL kill syntax is an exclusion and must not fire — both
    // the family kill (`!RC4`, `:-3DES`) and a killed compound suite name
    // (`!EDH-RSA-DES-CBC3-SHA`), which the variable-length lookbehind rejects by
    // scanning back to the component start for a leading `!`/`-`. The SAME kill
    // lookbehind guards the TLS_RSA_ arm: `!TLS_RSA_WITH_…` / `-TLS_RSA_WITH_…`
    // explicitly EXCLUDES the static-RSA suite and is remediation, not exposure.
    regex: /\bssl_ciphers\b[^\n]*(?:(?<!(?:^|[\s:,"'=])[!-][\w-]{0,64})(?:(?<![!\w-])|(?<=\w-))(?:RC4|3?DES)\b|(?<!(?:^|[\s:,"'=])[!-][\w-]{0,64})\bTLS_RSA_WITH_)/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["config", "yaml"],
    pqcReplacement: "AES-256-GCM suites with ECDHE today; hybrid PQC key exchange (ML-KEM) as it lands in TLS stacks",
  },
  {
    id: "tls-legacy-protocol-apache",
    family: "Asymmetric",
    algorithm: "Legacy TLS protocol (SSLv3/TLS 1.0/1.1)",
    description: "Apache SSLProtocol enabling SSLv3, TLSv1, or TLSv1.1",
    // Apache's +/- syntax: `-SSLv3` REMOVES a protocol, so the canonical hardening
    // line `SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1` must not fire — the lookbehind
    // rejects a token preceded by `-`. A bare or `+`-prefixed legacy token enables.
    regex: /\bSSLProtocol\b[^\n]*(?<![-\w])\+?(?:SSLv3|TLSv1(?:\.[01])?)(?![.\d])/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["config", "yaml"],
    pqcReplacement: "TLS 1.3 (hybrid PQC key exchange, e.g. X25519MLKEM768, where supported); TLS 1.2 + ECDHE as the transitional floor",
  },
  {
    id: "tls-weak-cipher-apache",
    family: "SymmetricLegacy",
    algorithm: "Weak TLS cipher suite (RC4/DES/3DES or static-RSA key exchange)",
    description: "Apache SSLCipherSuite enabling RC4, DES/3DES, or TLS_RSA_ (static RSA) suites",
    // Same enabled-vs-killed component logic as tls-weak-cipher-nginx (the kill
    // lookbehind covers the TLS_RSA_ arm too).
    regex: /\bSSLCipherSuite\b[^\n]*(?:(?<!(?:^|[\s:,"'=])[!-][\w-]{0,64})(?:(?<![!\w-])|(?<=\w-))(?:RC4|3?DES)\b|(?<!(?:^|[\s:,"'=])[!-][\w-]{0,64})\bTLS_RSA_WITH_)/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["config", "yaml"],
    pqcReplacement: "AES-256-GCM suites with ECDHE today; hybrid PQC key exchange (ML-KEM) as it lands in TLS stacks",
  },
  {
    id: "tls-legacy-haproxy",
    family: "Asymmetric",
    algorithm: "Legacy TLS protocol or weak cipher (HAProxy bind defaults)",
    description: "HAProxy ssl-default-bind-options/-ciphers enabling legacy TLS or weak suites",
    // `no-sslv3` / `no-tlsv10` DISABLE and must not fire; only `force-*` pins to a
    // legacy version and `ssl-min-ver` set to a legacy floor count as exposure.
    // The ciphers arm shares the tls-weak-cipher-nginx kill-lookbehind logic,
    // including on the TLS_RSA_ (static-RSA suite) alternative.
    regex: /\bssl-default-bind-(?:options\b[^\n]*\b(?:force-sslv3|force-tlsv1[01]\b|ssl-min-ver\s+(?:SSLv3|TLSv1(?:\.[01])?(?![.\d])))|ciphers\b[^\n]*(?:(?<!(?:^|[\s:,"'=])[!-][\w-]{0,64})(?:(?<![!\w-])|(?<=\w-))(?:RC4|3?DES)\b|(?<!(?:^|[\s:,"'=])[!-][\w-]{0,64})\bTLS_RSA_WITH_))/,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["config", "yaml"],
    pqcReplacement: "ssl-min-ver TLSv1.2 (prefer TLSv1.3) with AES-256-GCM/ECDHE suites; hybrid PQC key exchange as it lands",
  },
  {
    id: "ssh-classical-kex",
    family: "DH",
    algorithm: "Classical SSH key exchange (no PQC hybrid)",
    description: "OpenSSH KexAlgorithms restricted to classical key exchange (ecdh-*/diffie-hellman-*) with no PQC hybrid",
    // Three conditions in one line-shape: (1) the value is not a removal
    // (`KexAlgorithms -…` deletes algorithms — remediation); (2) NO PQC hybrid
    // (sntrup*/mlkem*) appears anywhere in the value — a hybrid-first list is the
    // fixed posture and must not fire; (3) a classical kex family is present.
    regex: /\bKexAlgorithms\b(?!\s*=?\s*-)(?![^\n]*\b(?:sntrup|mlkem))[^\n]*\b(?:ecdh-sha2-|diffie-hellman-)/i,
    quantumVulnerable: true,
    baseSeverity: "high",
    languages: ["config", "yaml"],
    pqcReplacement: "Enable a PQC hybrid key exchange first in the list (sntrup761x25519-sha512 or mlkem768x25519-sha256, OpenSSH 9.x+)",
  },

  // PKCS#12 keystore (.pfx/.p12) — bundles an RSA/EC private key + cert chain.
  // The library/API token or a quoted keystore path; trailing \b on `pkcs12`
  // keeps it off identifiers like `pkcs12Loader`.
  {
    id: "pkcs12-keystore",
    family: "Asymmetric",
    algorithm: "PKCS#12 keystore (key + cert)",
    description: "PKCS#12 / PFX keystore reference",
    regex: /\bpkcs12\b|["'][^"']*\.p(?:fx|12)["']/i,
    quantumVulnerable: true,
    baseSeverity: "medium",
    languages: ["go", "csharp", "java", "javascript", "typescript", "python", "config", "yaml", "any"],
    pqcReplacement: "Re-issue the keystore's key and certificate with PQC (ML-DSA / ML-KEM)",
  },
];

const KEY_BITS_RE = /\b(512|768|1024|2048|3072|4096|256|384|521|128)\b/;

/** Best-effort key-size extraction from the matched line. */
export function extractKeyBits(line: string, family: string): number | null {
  const m = line.match(KEY_BITS_RE);
  if (!m) return null;
  const bits = Number(m[1]);
  // Curve sizes (256/384/521) only meaningful for ECC.
  if (family === "ECC") return [256, 384, 521].includes(bits) ? bits : null;
  if (family === "RSA" || family === "DSA" || family === "DH") {
    return [512, 768, 1024, 2048, 3072, 4096].includes(bits) ? bits : null;
  }
  return [128, 256].includes(bits) ? bits : null;
}

/**
 * Detection confidence per pattern: how strongly a match implies actual crypto
 * USAGE versus a mention (a name/number in a string, enum, doc, or config token).
 * Regex sees text, not call-sites, so name/enum matchers are down-ranked. Patterns
 * not listed default to "high" — they match a library call-site or key material
 * (e.g. `mbedtls_rsa_gen_key(`, `KeyPairGenerator.getInstance("RSA")`, a PEM block).
 */
const PATTERN_CONFIDENCE: Record<string, Confidence> = {
  // "low" = possible mention: fires on the bare algorithm name/number anywhere
  // (a JWT alg in an enum, a curve name in a doc, `bits = 2048` on any variable).
  // Excluded from the posture grade and the headline count; surfaced for review.
  "ecc-curve-decl": "low",
  "ecc-ed25519": "low",
  "rsa-modulus-bits": "low",
  "jwt-rsa-alg": "low",
  "jwt-ecdsa-alg": "low",
  // "medium" = a name/config token that is usually real but can be a mention.
  "ssh-rsa-key": "medium",
  "ssh-ecdsa-key": "medium",
  "dsa-usage": "medium",
  "dh-keyexchange": "medium",
  "sym-des-3des": "medium",
  "sym-aes128": "medium",
  "hash-md5-sha1": "medium",
  "tls-rsa-cert": "medium",
};

/** Detection confidence for a finding, by the pattern that matched it. */
export function confidenceFor(patternId: string): Confidence {
  return PATTERN_CONFIDENCE[patternId] ?? "high";
}

// Patterns whose match IS a concrete cryptographic value — key material (PEM/PGP
// blocks), an SSH public-key line, or an X.509 signature-algorithm token. When
// these fire, the matched text is the artifact itself, real regardless of any
// surrounding words (a canonical SSH key `ssh-rsa <blob> user@host` is multi-word
// by convention; a private-key block embedded in a string is still a key). So
// per-occurrence context must never downgrade these to a "possible mention".
const KEY_MATERIAL = new Set<string>([
  "rsa-pem-header",
  "pkcs8-pem-private-key",
  "rsa-pgp-private-block",
  "ecc-pem-header",
  "dsa-pem-header",
  "openssh-pem-private-key",
  "pkcs8-encrypted-pem",
  "pgp-public-block",
  "jwk-asymmetric-key",
  "x509-cert-body",
  "ssh-rsa-key",
  "ssh-ecdsa-key",
  "tls-rsa-cert",
]);

/**
 * Final per-occurrence confidence: the pattern's base confidence, refined by the
 * syntactic context of *this* match (ENG-01a). A crypto name sitting in a PROSE
 * string — a log line, an error message, a doc comment rendered as a string — is
 * a *mention*, not a use, so it is capped to "low" (possible mention, excluded
 * from the grade and headline count). Key material is real anywhere and is never
 * downgraded.
 *
 * ── POLICY SEAM ──────────────────────────────────────────────────────────────
 * This is the one knob worth a human's judgment: how aggressively should context
 * override a pattern's base confidence? It only ever *downgrades* a match to
 * "low" — it never fabricates or upgrades a finding, so it cannot create a false
 * positive, only reclassify one as a possible mention. Two context signals
 * downgrade:
 *  - `mention`: the name sits in a prose string (log/error/doc) or a URL/route
 *    path slug — a reference, not a use. Respects the never-downgrade rule for
 *    key material.
 *  - `disabled`: the name is a config key explicitly turned off (`"ssh-rsa":
 *    false`). This is the sole signal allowed to override never-downgrade — a
 *    disabled algorithm is not a live exposure, no matter how concrete the token.
 *  - `enumRef`: the name is a bare read of an algorithm enum/class constant
 *    (`= SignatureAlgorithm.DSA`) — a reference, not an operation. The zero-dep
 *    stand-in for the call-vs-reference data flow a full AST would give.
 * A stricter policy (e.g. also downgrade single-token strings for medium
 * patterns) would trade recall for precision; a looser one would surface more as
 * real. Tune here.
 */
// JOSE algorithm-identifier patterns whose base confidence is deliberately "low"
// (the token can be a config label, e.g. `["RS256"]`). But when the SAME token is
// a bare CODE identifier — a typed constant declaration like
// `SignatureAlgorithm RS256 = …` in a Java/Kotlin crypto library — it is a real
// use, not a label, so it earns "medium". A token that only ever appears as a
// string value is NOT upgraded (stays a low possible-mention).
const CODE_TOKEN_UPGRADE = new Set<string>(["jwt-rsa-alg", "jwt-ecdsa-alg"]);

// SSH key patterns match the key-TYPE NAME (`ssh-rsa`, `ecdsa-sha2-nistp256`). A
// real key line carries the name PLUS a base64 blob; a bare name in prose does not.
// These are the KEY_MATERIAL patterns whose never-downgrade protection may yield for
// a prose mention when the match is a bare name (`bareKeyName`) — a real key line
// keeps its protection because the blob makes `bareKeyName` false.
const SSH_KEY_NAME = new Set<string>(["ssh-rsa-key", "ssh-ecdsa-key"]);

// Patterns that match a PEM `-----BEGIN …-----` header. An EMPTY block (BEGIN
// immediately followed by END, no base64 body) is a placeholder / negative test
// input, not key material, so it is allowed to downgrade despite never-downgrade.
export const PEM_HEADER = new Set<string>([
  "rsa-pem-header", "pkcs8-pem-private-key", "rsa-pgp-private-block", "ecc-pem-header",
  "dsa-pem-header", "openssh-pem-private-key", "pkcs8-encrypted-pem", "pgp-public-block",
  "x509-cert-body",
]);

export function resolveConfidence(
  patternId: string,
  ctx: {
    mention: boolean;
    disabled?: boolean;
    enumRef?: boolean;
    codeToken?: boolean;
    docstring?: boolean;
    ambiguous?: boolean;
    cryptoContext?: boolean;
    bareKeyName?: boolean;
    proseMention?: boolean;
    localeFile?: boolean;
    typeRef?: boolean;
    emptyPem?: boolean;
    importDecl?: boolean;
  },
): Confidence {
  const base = confidenceFor(patternId);
  if (ctx.emptyPem) return "low"; // an empty PEM block (BEGIN/END, no body) is a placeholder, not material
  if (ctx.disabled) return "low"; // explicit disable beats even never-downgrade
  if (ctx.localeFile) return "low"; // i18n/localization catalog value — UI text, never a use or key
  // A bare Go import declaration is a package dependency reference, not a crypto
  // operation — informational tier. The import still corroborates the file's real
  // call-site findings (it feeds hasCryptoContext), and in Go an unused import
  // does not compile, so the operation finding lives on the call-site line.
  if (ctx.importDecl) return "low";
  if (ctx.enumRef) return "low"; // a bare enum-constant read is a reference, not a use
  if (ctx.typeRef) return "low"; // a crypto type name in an annotation/subscript is a reference, not a use
  // An ambiguous SHAPE (`dh.generate`, `new DSA`, a bare `des3`/`md5sum`/`pkcs12`
  // token, a `.p12` filename) in a file that shows NO real crypto anywhere is a
  // coincidental application identifier, not a use — a possible mention. Real crypto
  // files corroborate (`hasCryptoContext`), so a genuine use keeps its confidence.
  if (ctx.ambiguous && !ctx.cryptoContext) return "low";
  // A bare code JOSE-alg token (`SignatureAlgorithm RS256 = …`) is a real use — but
  // only in a file that actually does JWT/JOSE crypto. A coincidental constant named
  // `ES256` ("east-storage-256") in non-crypto code stays a low possible-mention.
  if (ctx.codeToken && CODE_TOKEN_UPGRADE.has(patternId)) return ctx.cryptoContext ? "medium" : "low";
  // A prose mention downgrades — for key material only when it's inside a
  // triple-quoted docstring (unambiguous prose), or when the match is a bare ssh
  // key-type NAME appearing in NATURAL-LANGUAGE prose (a log/label) with no adjacent
  // key bytes (a name reference, not a key). Scoped to prose (`proseMention`) so a
  // key type named in a URL/route path (`/keys/ssh-rsa/import`) still wins the
  // never-downgrade rule; a real key line carries the blob, so it never qualifies.
  const keyMaterialYields =
    ctx.docstring || (SSH_KEY_NAME.has(patternId) && ctx.bareKeyName && ctx.proseMention);
  if (ctx.mention && (!KEY_MATERIAL.has(patternId) || keyMaterialYields)) return "low";
  return base;
}

export function patternCount(): number {
  return PATTERNS.length;
}
