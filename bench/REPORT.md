# UniQueS benchmark report

Results for the two independent benchmarks. Methodology and scope in
[`README.md`](README.md). Everything here is reproducible from the pinned inputs;
the per-finding labels are in [`repos/labels/`](repos/labels/).

_Engine: UniQueS v0.7.0. Each benchmark drove real engine fixes; where a fix
changed a number, both the before and after are shown so the improvement is
auditable, not asserted._

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

**Headline: 88.6% precision (931 TP / 120 FP) across 20 repos, full coverage (0
unlabeled).** Separately, **683 X.509 certificates** were discovered and parsed; a
successful DER parse is mechanical proof a certificate exists, so certificates are
inventoried but **excluded from the precision denominator** (counting them as
hand-adjudicated TPs would inflate the number this benchmark exists to measure). Four
repos that delegate crypto to their platform or stdlib (**gin, express, lodash**) or
vendor it out (**libsodium**'s shallow tree) produced **zero findings** — the negative
controls, proving the tool does not invent crypto.

**Why this is lower than the 95.9% previously reported (and why that is the honest
move).** The earlier number adjudicated only the first ~60 findings per repo; the
uncounted tail was asserted "TP-leaning" but never labeled. This release removes the
cap and labels the whole tail — 650 additional findings across the six largest repos.
The number is measured, not tuned, and it went *down* because the previously-hidden
tail includes real false positives (see vault below). A precision number you can only
quote by capping the sample is not a precision number.

| Repo | Lang | Kind | Actionable | TP | FP | Certs | Precision |
|---|---|---|---:|---:|---:|---:|---:|
| caddyserver/caddy | Go | app | 18 | 18 | 0 | 7 | 100% |
| go-gitea/gitea | Go | app | 61 | 61 | 0 | 0 | 100% |
| gin-gonic/gin | Go | framework (control) | 0 | 0 | 0 | 0 | — |
| openssh/openssh-portable | C | SSH lib | 115 | 110 | 5 | 0 | 95.7% |
| jwtk/jjwt | Java | JWT lib | 60 | 60 | 0 | 0 | 100% |
| auth0/node-jsonwebtoken | JS | JWT lib | 5 | 3 | 2 | 0 | 60% |
| pyca/cryptography | Python | crypto lib | 208 | 191 | 17 | 542 | 91.8% |
| paramiko/paramiko | Python | SSH lib | 68 | 67 | 1 | 0 | 98.5% |
| syncthing/syncthing | Go | TLS app | 10 | 10 | 0 | 0 | 100% |
| hashicorp/vault | Go | secrets app | 281 | 189 | 92 | 68 | 67.3% |
| smallstep/certificates | Go | CA | 188 | 186 | 2 | 60 | 98.9% |
| FiloSottile/age | Go | encryption tool | 12 | 12 | 0 | 0 | 100% |
| rustls/rustls | Rust | TLS lib | 5 | 5 | 0 | 6 | 100% |
| jedisct1/libsodium | C | crypto lib (control) | 0 | 0 | 0 | 0 | — |
| jpadilla/pyjwt | Python | JWT lib | 9 | 9 | 0 | 0 | 100% |
| psf/requests | Python | HTTP lib | 3 | 3 | 0 | 0 | 100% |
| expressjs/express | JS | framework (control) | 0 | 0 | 0 | 0 | — |
| lodash/lodash | JS | utils (control) | 0 | 0 | 0 | 0 | — |
| prometheus/prometheus | Go | monitoring app | 2 | 1 | 1 | 0 | 50% |
| etcd-io/etcd | Go | mTLS store | 6 | 6 | 0 | 0 | 100% |

Certificate columns (caddy 7, pyca 542, vault 68, step-ca 60, rustls 6) are v0.7.0's
X.509 parser inventorying real certs — mostly the pyca/step-ca test-vector corpora.
They are excluded from precision, as noted above.

### Where the false positives are — and the one honest fix left on the table

**120 FPs, and 92 of them are in vault (67.3%).** vault is a large Go monolith, and
**79 of its 92 FPs are bare `import "crypto/ecdsa"` / `"crypto/rsa"` / `"crypto/dsa"`
lines.** Per the documented convention this benchmark has used since the 9-repo
version, an import line is labeled **FP**: it is not a use site, and the actual
`ecdsa.GenerateKey(...)` call it implies is separately labeled TP, so counting the
import too would double-count the same usage. We kept that convention rather than
flip it to rescue the number — reclassifying to lift a metric is precisely the
"grade your own exam" trap.

This points at a **real, legitimate engine-precision opportunity** (tracked for the
next engine release, NOT chased here to avoid overfitting to this corpus): a Go
`import` line that only *names* a crypto package should be a low-confidence mention,
not an actionable finding, when the package's real call sites are surfaced separately.
Demoting import-only lines — with a qbench guard proving `ecdsa.GenerateKey` still
fires — would recover most of the vault gap *honestly*, by fixing detection rather
than by relabeling. That is the difference between 88.6% earned and 95.9% asserted.

The prior **general** engine fixes still hold and still help any codebase:

| Class fixed | Version | How |
|---|---|---|
| Crypto names / key-armor in i18n localization catalogs | v0.6.0 | `isLocaleResourceFile` |
| Python type-annotation references (`-> X`, `Union[…]`, `type[…]`) | v0.6.1 | `isTypeReferenceAt` |
| INI leading-`;` comments (`;; openssl …`) | v0.6.1 | config-lang comment masking |
| Empty PEM blocks (BEGIN/END, no body) | v0.6.1 | `isEmptyPemBlockAt` |
| (v0.6.0 NIST recall fixes — see §1) | v0.6.0 | pattern restructure |

Remaining FP classes beyond the vault import lines (tracked in `KNOWN_GAPS`, not
chased): pyca `isinstance`/accepted-types tuples (~13), openssh denylist-removal +
log-string echo (5), jsonwebtoken `RSA-PSS` in an interpolated template (2),
prometheus (1), paramiko dispatch-table edge (1), step-ca (2).

### Caveats (still honest)

- **No cap any more.** Every actionable finding in all 20 repos is labeled; the
  previous "first-60" cap is gone. This is the change that moved the headline.
- **The convention call is disclosed, not hidden.** Go import lines = FP is a
  defensible-either-way choice; we state it plainly and keep it consistent across the
  whole corpus rather than switching it per repo to flatter the number.
- **Certificates are inventoried, not adjudicated.** 683 parsed certs are reported as
  their own column and kept out of the precision math (a DER parse is proof, not a
  judgment call).
- **Precision, not exhaustive recall.** Recall notes per repo are in the labels'
  source; obvious misses (e.g. Ed25519 under-surfacing) are logged, not hidden.
- **Crypto-dense libraries are the easy case.** The apps (gitea, vault, prometheus,
  etcd) and the four negative controls are what keep this honest — and vault at 67.3%
  is exactly the kind of number a capped benchmark would have buried.

---

## Reproduce

```bash
npm --prefix server run build                       # build the engine once
cd bench/sard && ./download.sh && node score.mjs    # NIST recall
cd ../repos && node run.mjs                          # real-repo precision vs published labels
```
