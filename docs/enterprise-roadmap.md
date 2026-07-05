# UniQueS enterprise roadmap

The plan to take the on-prem platform from "commercial v0.1" to a full-fledged
enterprise product a regulated mid-market security team can standardize on. Built by
the worker team (`.claude/agents/`), reviewed adversarially before every commit.
Division of labor: the founder owns GTM/marketing; the workers own the product.

## Design invariants (never traded away)

- **Zero new runtime dependencies. Air-gapped. Pure JS.** Every feature works
  offline, no phone-home. This is the moat against IBM/SandboxAQ — "your source
  never leaves your network." (`@noble/post-quantum` is the only crypto dep.)
- **The free CLI is never gated.** Enterprise features live in the platform.
- **Fail closed.** Auth/role/license gates deny on error, never open.
- **Honest by construction.** No silent scan skips, no hidden findings, no
  self-graded metrics quoted as benchmarks. Learning re-ranks, never suppresses.

## On "reinforcement learning" — the honest translation

The enterprise differentiator the CEO asked for as "RL" is an **online triage
learning loop**, and it IS reinforcement learning in the true sense (learn a policy
from a reward signal) — without the dishonesty of claiming a trained neural model in
a zero-dependency air-gapped product:

- **Reward signal:** every finding a customer triages — `confirm` (real, act on it),
  `dismiss` (false positive / not relevant), `accept-risk`.
- **Policy:** per `(org, patternId)`, a Beta-Bernoulli posterior `Beta(α, β)` —
  `α += confirms`, `β += dismisses` — **seeded from our published 20-repo benchmark
  label counts** as the global prior (a pattern at 100% bench precision starts
  confident; a noisier one starts skeptical).
- **Action:** the posterior mean re-ranks future findings' priority for that org.
  A pattern the team keeps dismissing sinks; one they keep confirming rises. The
  pitch writes itself: *the scanner gets more precise on your codebase every week.*
- **Hard safety rules (qa-adversary enforces):** (1) learning **re-ranks, never
  hides** — a finding can lose priority but is never silently suppressed; (2)
  KEY_MATERIAL never drops below visible; (3) **per-org isolation** — one tenant's
  feedback never touches another's ranking; (4) **deterministic** — same verdict
  history ⇒ same ranking; (5) **explainable** — "ranked lower: your team dismissed
  9/10 similar findings."

## Phases (dependency-ordered)

### E1 — Enterprise foundation · platform-engineer
The bedrock every other feature needs. Closes the security debt three external
critiques flagged as "real but premature" — now due.
- **RBAC**: per-membership roles `owner / admin / member / viewer`; `requireRole()`
  middleware; owner-only org settings, admin-only member management, viewer read-only.
- **Audit log**: `audit_log` table + `audit(ctx, action, target, meta)` called on
  every privileged mutation; queryable, exportable, immutable-append.
- **Session hardening**: httpOnly + SameSite cookies (not localStorage); session
  tokens hashed at rest (store sha256, not the raw token); constant-time compares.
- **API tokens**: scoped, hashed, revocable machine tokens for CI/automation
  (`Authorization: Bearer uqs_pat_…`), so the platform API is usable headless.

### E2 — Async scan infrastructure · platform-engineer
Scans currently run synchronously in the request path — fine for a demo, wrong for a
8,000-file estate. Move to a durable job queue.
- `scan_jobs` table (queued/running/done/failed/cancelled), an in-process worker
  tick (no external queue dep), progress + cancellation, resumable, per-org rate
  limits. Dashboard polls job status.

### E3 — Adaptive precision (the RL loop) · engine-engineer
The enterprise differentiator, on top of E1's org model + E2's job history.
- Triage endpoints (confirm/dismiss/accept-risk on a finding identity), the
  Beta-Bernoulli calibration store seeded from `bench/repos` priors, per-org
  posterior updates, and a ranking pass that adjusts priority (never confidence,
  never visibility). Explanations surfaced in the finding detail.

### E4 — Enterprise integrations · platform-engineer + engine-engineer
- **SSO** (OIDC — offline-verifiable, no runtime phone-home to the IdP beyond the
  standard flow), **SIEM/webhook export** (SARIF/CBOM push on scan completion),
  **continuous monitoring** (extend `monitor/` — scheduled re-scans + drift alerts),
  **data retention** policies, **compliance report** scheduling.

## Cadence

One phase at a time, each: worker builds → `qa-adversary` reviews → fix → integrate
→ tests+qbench+SARD+self-scan green → commit → tag a minor release. The founder can
redirect priority at any phase boundary. Each release keeps CI green and the
benchmark numbers honest.
