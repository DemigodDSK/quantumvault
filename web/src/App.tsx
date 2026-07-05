import { useEffect, useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Assets from "./pages/Assets";
import Risk from "./pages/Risk";
import Compliance from "./pages/Compliance";
import Monitoring from "./pages/Monitoring";
import History from "./pages/History";
import AuthModal from "./components/AuthModal";
import LicenseBanner from "./components/LicenseBanner";
import { useAuth } from "./lib/auth";
import { getHealth } from "./lib/api";

/**
 * Show which QuantumVault build is running. In a self-hosted deployment this is
 * the *backend's* version (from /api/health) — so a stale container that's still
 * serving old code is visible at a glance. Falls back to the web build version
 * if the backend is unreachable. No phone-home: we never check for a newer
 * release (that would breach the air-gapped posture).
 */
function VersionTag() {
  const [info, setInfo] = useState<{ version: string; patterns?: number }>({ version: __APP_VERSION__ });
  useEffect(() => {
    getHealth()
      // An older backend may answer 200 without a `version` field — fall back to
      // the web build version rather than rendering "vundefined".
      .then((h) => setInfo({ version: h.version || __APP_VERSION__, patterns: h.patterns }))
      .catch(() => {
        /* backend unreachable — keep the web build version */
      });
  }, []);
  return (
    <div className="px-2 text-[10px] text-slate-600" title={`UniQueS v${info.version}`}>
      <span className="font-mono text-slate-500">v{info.version}</span>
      {info.patterns != null && <span> · {info.patterns} patterns</span>}
    </div>
  );
}

const NAV = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/assets", label: "Asset Inventory" },
  { to: "/risk", label: "Risk Analysis" },
  { to: "/compliance", label: "Compliance" },
  { to: "/monitoring", label: "Monitoring" },
  { to: "/history", label: "Scan History" },
];

function AuthPanel({ onSignIn }: { onSignIn: () => void }) {
  const { user, logout } = useAuth();
  if (user) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
        <div className="text-[11px] uppercase tracking-wider text-slate-500">Signed in</div>
        <div className="truncate text-sm font-semibold text-slate-200">{user.orgName}</div>
        <div className="truncate text-xs text-slate-400">{user.email}</div>
        <button
          onClick={logout}
          className="mt-2 w-full rounded-md border border-slate-700 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-slate-800"
        >
          Sign out
        </button>
      </div>
    );
  }
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
      <div className="text-xs text-slate-400">Viewing demo data.</div>
      <button
        onClick={onSignIn}
        className="mt-2 w-full rounded-md bg-indigo-500 py-1.5 text-xs font-semibold text-white transition hover:bg-indigo-400"
      >
        Sign in to scan
      </button>
    </div>
  );
}

function Sidebar({ onSignIn }: { onSignIn: () => void }) {
  return (
    <aside className="flex flex-col border-b border-slate-800 bg-slate-950/80 px-4 py-4 lg:fixed lg:inset-y-0 lg:left-0 lg:w-60 lg:border-b-0 lg:border-r lg:py-6">
      <div className="flex items-center gap-2 px-2">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-indigo-500 to-cyan-400 text-lg font-black text-slate-950">
          U
        </div>
        <div>
          <div className="text-sm font-bold tracking-tight text-white">UniQueS</div>
          <div className="text-[10px] uppercase tracking-widest text-slate-500">Universal Quantum Scanner</div>
        </div>
      </div>

      <nav className="mt-4 flex flex-wrap gap-1 lg:mt-8 lg:block lg:space-y-1">
        {NAV.map((n) => (
          <NavLink
            key={n.to}
            to={n.to}
            end={n.end}
            className={({ isActive }) =>
              `block rounded-lg px-3 py-2 text-sm font-medium transition ${
                isActive
                  ? "bg-indigo-500/15 text-indigo-300"
                  : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200"
              }`
            }
          >
            {n.label}
          </NavLink>
        ))}
      </nav>

      <div className="mt-4 space-y-3 lg:mt-auto">
        <AuthPanel onSignIn={onSignIn} />
        <div className="hidden rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-[11px] text-slate-500 lg:block">
          <div className="font-semibold text-slate-400">Post-Quantum Ready</div>
          NIST ML-KEM · ML-DSA · SLH-DSA migration tracking
        </div>
        <VersionTag />
      </div>
    </aside>
  );
}

const IS_DEMO = __DEMO__;

function DemoBanner() {
  return (
    <div className="flex flex-wrap items-center justify-center gap-x-2 gap-y-1 border-b border-violet-500/30 bg-violet-500/10 px-6 py-2 text-center text-xs text-violet-100 lg:ml-60">
      <span className="font-semibold">Live demo</span>
      <span className="text-violet-200/80">
        — read-only, populated by scanning real OSS libraries (auth0/node-jsonwebtoken, pyjwt, golang-jwt, paramiko).
      </span>
      <a
        href="https://github.com/uni-que-s/uniques"
        className="font-semibold text-white underline decoration-violet-400 underline-offset-2 hover:text-violet-200"
      >
        Install it to scan your own code →
      </a>
    </div>
  );
}

export default function App() {
  const [authOpen, setAuthOpen] = useState(false);
  return (
    <div className="min-h-screen">
      <Sidebar onSignIn={() => setAuthOpen(true)} />
      {IS_DEMO ? <DemoBanner /> : <LicenseBanner />}
      <main className="px-4 py-5 lg:ml-60 lg:px-8 lg:py-7">
        <Routes>
          <Route path="/" element={<Dashboard onRequireAuth={() => setAuthOpen(true)} />} />
          <Route path="/assets" element={<Assets />} />
          <Route path="/risk" element={<Risk />} />
          <Route path="/compliance" element={<Compliance />} />
          <Route path="/monitoring" element={<Monitoring onRequireAuth={() => setAuthOpen(true)} />} />
          <Route path="/history" element={<History />} />
        </Routes>
      </main>
      {authOpen && <AuthModal onClose={() => setAuthOpen(false)} />}
    </div>
  );
}
