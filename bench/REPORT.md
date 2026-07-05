# UniQueS benchmark report

Results for the two independent benchmarks. Methodology and scope in
[`README.md`](README.md). Everything here is reproducible from the pinned inputs;
the per-finding labels are in [`repos/labels/`](repos/labels/).

_Engine: UniQueS v0.7.x (v0.7.0 plus the Go-import informational-tier demotion).
Each benchmark drove real engine fixes; where a fix changed a number, both the
before and after are shown so the improvement is auditable, not asserted._

---

## 1. NIST SARD / Juliet (official labeled corpus)

Recall against the U.S. NIST **Software Assurance Reference Dataset**, Juliet Java
1.3, CWE-327 (broken crypto) + CWE-328 (reversible hash).

| Algorithm | Cases | Recall | Scope |
|---|---:|---:|---|
| DES | 17 | **100%** | in scope |
| 3DES / DESede | 17 | **100%** | in scope |
| MD5 | 17 | **100%** | in scope |
| SHA-1 | 17 | **100%** | in scope |
| **In-scope total** | **68** | **100.0%** | |
| MD2 | 17 | 0% | out of scope (obsolete; not a claimed pattern) |

**Scope boundary (do not overstate):** Juliet's crypto cases are the *classical*
threat model — DES/MD5/SHA-1 are the flaw, AES/SHA-256 the "safe" answer. It
contains **no RSA/ECC/DSA/DH** cases. So this is 100% on the legacy symmetric/hash
slice of our scope only; the quantum core is measured by benchmark 2.

**Value delivered:** on first run this scored **0% on DES/MD5/SHA-1** — a trailing
`\b` a closing quote can never satisfy silently dropped `createHash('md5')`,
`MessageDigest.getInstance("MD5")`, and `getInstance("DES")` entirely, plus a
`"SHA1"`-vs-`"SHA-1"` gap. qbench never caught these (we never wrote those exact
fixtures). Fixed in v0.6.0, now gated in qbench.

---

## 2. Reproducible public-repo precision — 20 repositories

Precision on **twenty** pinned, well-known repositories. **Every** actionable finding
is now hand-labeled TP/FP by reading the cited source — no per-repo cap — and every FP
was re-checked by an independent adversarial "try to refute" pass. Labels are published
per repo.

**Headline: 95.7% precision (852 TP / 38 FP) across 20 repos, full coverage (0
unlabeled).** Separately, **683 X.509 certificates** were discovered and parsed; a
successful DER parse is mechanical proof a certificate exists, so certificates are
inventoried but **excluded from the precision denominator** (counting them as
hand-adjudicated TPs would inflate the number this benchmark exists to measure). Four
repos that delegate crypto to their platform or stdlib (**gin, express, lodash**) or
vendor it out (**libsodium**'s shallow tree) produced **zero findings** — the negative
controls, proving the tool does not invent crypto.

**How 95.7% relates to the 88.6% previously reported — read this before quoting
either number.** v0.7.0 measured **88.6% (931 TP / 120 FP)** at full label coverage.
The Go-import demotion (this engine revision) re-tiers every bare Go `import
"crypto/…"` line to the **informational** tier (confidence `low`, machine-readable
`demotionReason: "import-declaration"`). Informational findings stay in every output
— JSON, SARIF (as `note`), CSV, CBOM, dashboard — but leave the *actionable* set this
benchmark measures. That moved the measured set in BOTH directions:

| Demoted out of the actionable set | Count | Where |
|---|---:|---|
| Import lines the labels adjudicated **FP** (bare import, no call-site corroboration in the labeled reading) | **82** | vault 81, prometheus 1 |
| Import lines the labels adjudicated **TP** (real import, file genuinely calls the package below) | **79** | step-ca 49, gitea 11, caddy 6, syncthing 5, etcd 5, age 3 |

So the headline moved 88.6% → 95.7% partly by removing false positives (120 → 38,
−82) and **partly by shrinking the measured set** (TP 931 → 852, −79; total −161
findings). The 79 demoted TPs are genuine crypto references per the published labels;
they are now informational because the same files' `GenerateKey(...)`-style call-site
findings remain actionable at full confidence, so the *worklist* loses no remediation
site. **The labels themselves are untouched** — the demoted import lines' TP/FP
adjudications remain in `labels/*.json` as ground truth; they simply no longer sit in
the actionable set the precision math runs over. If you want the number that is
insulated from the set-shrink effect: with imports still actionable and only the
labeled-FP imports removed, precision would be 96.1% (931/969) — the honest headline
stays 95.7% because that is what the tool actually measures as actionable.

| Repo | Lang | Kind | Actionable | TP | FP | Certs | Precision |
|---|---|---|---:|---:|---:|---:|---:|
| caddyserver/caddy | Go | app | 12 | 12 | 0 | 7 | 100% |
| go-gitea/gitea | Go | app | 50 | 50 | 0 | 0 | 100% |
| gin-gonic/gin | Go | framework (control) | 0 | 0 | 0 | 0 | — |
| openssh/openssh-portable | C | SSH lib | 115 | 110 | 5 | 0 | 95.7% |
| jwtk/jjwt | Java | JWT lib | 60 | 60 | 0 | 0 | 100% |
| auth0/node-jsonwebtoken | JS | JWT lib | 5 | 3 | 2 | 0 | 60% |
| pyca/cryptography | Python | crypto lib | 208 | 191 | 17 | 542 | 91.8% |
| paramiko/paramiko | Python | SSH lib | 68 | 67 | 1 | 0 | 98.5% |
| syncthing/syncthing | Go | TLS app | 5 | 5 | 0 | 0 | 100% |
| hashicorp/vault | Go | secrets app | 200 | 189 | 11 | 68 | 94.5% |
| smallstep/certificates | Go | CA | 139 | 137 | 2 | 60 | 98.6% |
| FiloSottile/age | Go | encryption tool | 9 | 9 | 0 | 0 | 100% |
| rustls/rustls | Rust | TLS lib | 5 | 5 | 0 | 6 | 100% |
| jedisct1/libsodium | C | crypto lib (control) | 0 | 0 | 0 | 0 | — |
| jpadilla/pyjwt | Python | JWT lib | 9 | 9 | 0 | 0 | 100% |
| psf/requests | Python | HTTP lib | 3 | 3 | 0 | 0 | 100% |
| expressjs/express | JS | framework (control) | 0 | 0 | 0 | 0 | — |
| lodash/lodash | JS | utils (control) | 0 | 0 | 0 | 0 | — |
| prometheus/prometheus | Go | monitoring app | 1 | 1 | 0 | 0 | 100% |
| etcd-io/etcd | Go | mTLS store | 1 | 1 | 0 | 0 | 100% |

(The v0.7.0 per-repo numbers before the demotion — e.g. caddy 18, gitea 61, vault
281 with 92 FP at 67.3% — are preserved in this file's git history at the 88.6%
revision.) Certificate columns (caddy 7, pyca 542, vault 68, step-ca 60, rustls 6)
are v0.7.0's X.509 parser inventorying real certs — mostly the pyca/step-ca
test-vector corpora. They are excluded from precision, as noted above.

### The Go-import demotion, stated precisely (2026-07-04)

A bare Go import line (`import "crypto/ecdsa"`, aliased/`_`/`.` variants, or a
grouped-block member) is a package **dependency declaration**, not a crypto
operation. The engine now demotes it to the informational tier with
`demotionReason: "import-declaration"` — **re-tiered, never hidden**: it remains in
JSON, SARIF (level `note`, zero security-severity), CSV (`confidence` /
`demotion_reason` columns), CBOM (`quantumvault:demotionReason` property), the
server database, and the dashboard ("possible mentions"). The actionable finding is
the call-site (`ecdsa.GenerateKey(...)`), which keeps full confidence — gated by
qbench and `go-import.test.ts` (raw-string, composite-literal, dot-import, and
cross-language guards).

One correction to what this report previously asserted: the published labels were
**not** a blanket "import line = FP" convention. Reading them back, the de-facto
convention was **uncorroborated import = FP, corroborated import = TP** (e.g.
caddy's `acme_test.go:5` import is labeled TP with the reason "file genuinely calls
ecdsa.GenerateKey(P256) below"). The demotion re-tiers both classes — which is why
the table above discloses the 79 labeled-TP demotions instead of describing the
change as an FP-only collapse.

The prior **general** engine fixes still hold and still help any codebase:

| Class fixed | Version | How |
|---|---|---|
| Crypto names / key-armor in i18n localization catalogs | v0.6.0 | `isLocaleResourceFile` |
| Python type-annotation references (`-> X`, `Union[…]`, `type[…]`) | v0.6.1 | `isTypeReferenceAt` |
| INI leading-`;` comments (`;; openssl …`) | v0.6.1 | config-lang comment masking |
| Empty PEM blocks (BEGIN/END, no body) | v0.6.1 | `isEmptyPemBlockAt` |
| (v0.6.0 NIST recall fixes — see §1) | v0.6.0 | pattern restructure |

Remaining FP classes (38 total; tracked in `KNOWN_GAPS`, not chased): pyca
`isinstance`/accepted-types tuples (~13), vault non-import residue (11), openssh
denylist-removal + log-string echo (5), jsonwebtoken `RSA-PSS` in an interpolated
template (2), paramiko dispatch-table edge (1), step-ca (2).

### Caveats (still honest)

- **No cap any more.** Every actionable finding in all 20 repos is labeled; the
  "first-60" cap that produced the withdrawn 95.9% is gone.
- **The set-shrink is disclosed, not hidden.** 95.7% is measured over an actionable
  set that the import demotion made 161 findings smaller — including 79 the labels
  call TP. Both movements (FP 120→38, TP 931→852) are stated above; quoting 95.7%
  without the shrink would overstate the pure-FP improvement (96.1% is the
  imports-stay-actionable counterfactual).
- **Labels are ground truth and were not edited.** The demotion is an engine tier
  change; `labels/*.json` — including the TP adjudications of now-demoted import
  lines — are byte-identical to the 88.6% revision.
- **Certificates are inventoried, not adjudicated.** 683 parsed certs are reported as
  their own column and kept out of the precision math (a DER parse is proof, not a
  judgment call).
- **Precision, not exhaustive recall.** Recall notes per repo are in the labels'
  source; obvious misses (e.g. Ed25519 under-surfacing) are logged, not hidden. One
  known recall edge from the demotion: in a file using Go's (lint-forbidden) dot
  import (`. "crypto/rsa"`) whose call-sites the patterns miss, the only remaining
  signal is the informational import line.
- **Crypto-dense libraries are the easy case.** The apps (gitea, vault, prometheus,
  etcd) and the four negative controls are what keep this honest — vault's 67.3%
  at v0.7.0 is exactly the kind of number a capped benchmark would have buried, and
  its residual 94.5% is real call-site precision, not import noise.

---

## Reproduce

```bash
npm --prefix server run build                       # build the engine once
cd bench/sard && ./download.sh && node score.mjs    # NIST recall
cd ../repos && node run.mjs                          # real-repo precision vs published labels
```
