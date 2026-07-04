# UniQueS benchmarks

Independent, reproducible accuracy measurement for the UniQueS crypto-discovery
engine. This directory exists so the numbers we quote are ones **you can re-run and
audit yourself** — not a score we assigned ourselves.

## Why three benchmarks (and why not just one)

Detection quality for a crypto *discovery* tool can't be captured by a single
number, and each instrument here answers a different question. Read them together.

| Instrument | Question it answers | Who owns the ground truth | Independence |
|---|---|---|---|
| **qbench** (`server/src/__tests__/qbench.fixtures.ts`) | *Did we regress?* | We do (hand-authored fixtures) | **None** — it's a gate, not a benchmark |
| **SARD** (`bench/sard/`) | *Do we catch the legacy weak-crypto NIST labels?* | **NIST** (official SARD/Juliet) | High — external labeled corpus |
| **repos** (`bench/repos/`) | *What's our precision on real, messy, third-party code?* | Public repos + our published labels | High — code we didn't write, labels you can audit |

> **We do not market qbench as a benchmark.** A suite where you wrote both the code
> and the answer key measures "still does what we decided," never "is it right" or
> "is it better than X." It's a regression gate. The two benchmarks below are the
> ones meant to be quoted.

---

## 1. NIST SARD / Juliet (`bench/sard/`)

**What:** recall against the U.S. NIST **Software Assurance Reference Dataset**,
specifically the Juliet Java 1.3 test cases for **CWE-327 (Use of a Broken or Risky
Cryptographic Algorithm)** and **CWE-328 (Reversible One-Way Hash)**. These are
government-maintained, independently-labeled test cases.

**Honest scope boundary — read this before quoting the number.** Juliet's crypto
cases were built for the *classical* threat model: they treat **DES, 3DES, MD5,
SHA-1, MD2** as the flaw and **AES / SHA-256** as the "safe" answer. That means:

- SARD measures our recall on the **legacy symmetric/hash slice** of our scope.
- It does **not** cover **RSA / ECC / DSA / Diffie-Hellman** — the *quantum*-vulnerable
  asymmetric algorithms that are the core of PQC migration. Juliet treats those as
  "safe," which is the opposite of the quantum threat model. So a high SARD score is
  necessary but **not sufficient** evidence of PQC-discovery quality. We say so
  rather than imply SARD blesses the whole tool.

**Result** (Juliet Java 1.3, in-scope algorithms):

| Algorithm | Juliet cases | Recall | Scope |
|---|---:|---:|---|
| DES | 17 | 100% | in scope |
| 3DES / DESede | 17 | 100% | in scope |
| MD5 | 17 | 100% | in scope |
| SHA-1 | 17 | 100% | in scope |
| **In-scope total** | **68** | **100%** | |
| MD2 | 17 | 0% | out of scope (obsolete; not a claimed pattern) |

**What SARD found that our own tests didn't.** Before we ran it, DES / MD5 / SHA-1
scored **0%** — three patterns had a trailing `\b` that a closing quote can never
satisfy, silently dropping `createHash('md5')`, `MessageDigest.getInstance("MD5")`,
and `getInstance("DES")` entirely, plus a missing `getInstance("DES")` arm and a
`"SHA1"`-vs-`"SHA-1"` mismatch. qbench never caught these because we never wrote
those exact fixtures. That is the entire argument for an external corpus. The gaps
are fixed in v0.6.0 and now gated in qbench.

**Reproduce:**

```bash
cd bench/sard
./download.sh          # fetches the official NIST Juliet Java 1.3 zip, extracts CWE-327/328
node score.mjs         # scans each case, prints per-algorithm recall
```

The 73 MB Juliet archive is **not** vendored here — `download.sh` pulls it from
`samate.nist.gov` so the corpus provenance stays with NIST.

---

## 2. Reproducible public-repo corpus (`bench/repos/`)

**What:** precision on **20** real, well-known open-source repositories, each pinned
to an exact commit, scanned, and with **every actionable finding hand-labeled TP/FP
by reading the cited source line**. Labels are published in `bench/repos/labels/` so
anyone can check our adjudication. Findings labeled TP were additionally re-checked
by an independent adversarial pass (skeptic-tries-to-refute). **Result: 88.6%
precision (931 TP / 120 FP), full coverage — no per-repo cap**, with **four negative
controls at zero findings**. (An earlier report quoted 95.9%, but only the first ~60
findings per repo were labeled; removing that cap and labeling the whole tail is what
moved the number — see [`REPORT.md`](REPORT.md) §2.) **683 X.509 certificates** are
discovered and inventoried separately, excluded from the precision denominator (a DER
parse is proof a cert exists, not a judgment call).

**Why this is the credible one for our actual task:** it's the exact job (find the
crypto in a codebase), on real messy code we didn't write, at fixed commits, with
auditable labels. This is the standard security tools are actually judged by.

**What it does and doesn't measure:** it measures **precision** (of the findings we
surface, how many are real) rigorously. It does **not** claim exhaustive **recall**
(finding *everything*) — measuring that needs a complete manual crypto audit of each
repo, which we don't assert. Obvious misses spotted during adjudication are logged
in each repo's notes, not swept away.

The corpus deliberately mixes **crypto-dense libraries** (where precision is the
"easy" case) with **real application code** and a **near-negative control** (a web
framework that delegates crypto to the stdlib) — so the number isn't earned only on
the flattering inputs, which was the honest weakness of our earlier one-off report.

See [`bench/repos/manifest.json`](repos/manifest.json) for the pinned set and
[`REPORT.md`](REPORT.md) for the results and per-repo breakdown.

**Reproduce:**

```bash
cd bench/repos
node run.mjs           # clones each pinned repo, scans, compares to published labels
```

---

## The honest one-paragraph summary

UniQueS scores **100% recall on the in-scope NIST SARD legacy-crypto labels** (an
external, government dataset — which also caught real gaps our own suite missed),
and **88.6% precision across 20 pinned public repositories** — every actionable
finding labeled, no cap — with per-finding labels published for audit, spanning
libraries, applications, and four negative controls. SARD does not cover the RSA/ECC
quantum core (it predates the threat model), so the real-repo corpus — not SARD — is
the evidence for full-scope discovery quality. `qbench` is our regression gate and is
not quoted as a benchmark.
