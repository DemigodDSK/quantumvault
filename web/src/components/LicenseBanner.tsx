import { useEffect, useState } from "react";
import { getLicense, activateLicense, type LicenseStatus } from "../lib/api";

/**
 * Trial / license banner for the self-hosted platform. Renders nothing while a
 * comfortably-valid license is active; nudges as a trial winds down; and locks
 * loudly (with an activation field) once the trial or license has lapsed. The
 * free CLI is never affected — this is purely the platform entitlement surface.
 *
 * Only mounted outside the public demo build (the demo has no real backend).
 */

const RENEWAL_NUDGE_DAYS = 14; // start nudging a licensed instance this close to expiry

type Tone = "info" | "warn" | "lock";
const TONE: Record<Tone, string> = {
  info: "border-indigo-500/30 bg-indigo-500/10 text-indigo-100",
  warn: "border-amber-500/40 bg-amber-500/10 text-amber-100",
  lock: "border-rose-500/40 bg-rose-500/10 text-rose-100",
};

export default function LicenseBanner() {
  const [lic, setLic] = useState<LicenseStatus | null>(null);
  const [open, setOpen] = useState(false);
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getLicense()
      .then(setLic)
      .catch(() => {
        /* backend unreachable — stay silent rather than alarm the operator */
      });
  }, []);

  if (!lic) return null;

  // Decide whether (and how loudly) to show.
  const isReadOnly = lic.readOnly; // resting state: viewing only
  const isGrace = lic.state === "grace";
  const expiringSoon = lic.state === "licensed" && lic.daysRemaining <= RENEWAL_NUDGE_DAYS;
  if (lic.state === "licensed" && !expiringSoon) return null; // fully licensed, plenty of runway
  const tone: Tone = isReadOnly ? "lock" : isGrace || expiringSoon ? "warn" : "info";
  const heading = isReadOnly ? "Read-only" : isGrace ? "Grace period" : lic.state === "trial" ? "Trial" : "License";

  async function onActivate() {
    setBusy(true);
    setError(null);
    try {
      const next = await activateLicense(key.trim());
      setLic(next);
      setOpen(false);
      setKey("");
      // Re-fetch the (now-unlocked) pages cleanly.
      if (next.active) window.location.reload();
    } catch (e: unknown) {
      const msg =
        (e as { response?: { data?: { error?: string } } })?.response?.data?.error ??
        "Could not activate that key. Check it and try again.";
      setError(msg);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={`border-b px-4 py-2 text-xs sm:px-6 lg:ml-60 ${TONE[tone]}`}>
      <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1 text-center">
        <span className="font-semibold">{heading}</span>
        <span className="opacity-90">{lic.message}</span>
        <button
          onClick={() => setOpen((v) => !v)}
          className="rounded-md border border-white/25 px-2 py-0.5 font-semibold underline-offset-2 hover:underline"
        >
          {open ? "Cancel" : isReadOnly || isGrace ? "Activate a license key" : "Enter license key"}
        </button>
      </div>

      {open && (
        <div className="mx-auto mt-2 flex max-w-2xl flex-wrap items-center justify-center gap-2">
          <textarea
            value={key}
            onChange={(e) => setKey(e.target.value)}
            placeholder="Paste your UQS2.… key (post-quantum keys are long)"
            spellCheck={false}
            rows={2}
            className="min-w-0 flex-1 resize-y rounded-md border border-slate-700 bg-slate-950/70 px-2 py-1 font-mono text-[11px] leading-tight text-slate-100 placeholder:text-slate-600 focus:border-indigo-400 focus:outline-none"
          />
          <button
            onClick={onActivate}
            disabled={busy || key.trim().length === 0}
            className="rounded-md bg-indigo-500 px-3 py-1 font-semibold text-white transition hover:bg-indigo-400 disabled:opacity-50"
          >
            {busy ? "Activating…" : "Activate"}
          </button>
        </div>
      )}
      {error && <div className="mt-1 text-center text-[11px] text-rose-300">{error}</div>}
    </div>
  );
}
