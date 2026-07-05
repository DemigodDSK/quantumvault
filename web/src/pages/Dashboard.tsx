import { useEffect, useState } from "react";
import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  Bar,
  BarChart,
  XAxis,
  YAxis,
} from "recharts";
import {
  getDashboard,
  getRiskConfig,
  runScan,
  runGitScan,
  type Dashboard as DashboardData,
  type AssetStatus,
  type RiskConfig,
} from "../lib/api";
import { Card, StatCard, StatusBadge, ASSET_STATUS_META, FAMILY_COLOR, SEVERITY_COLOR } from "../components/ui";
import { computePosture } from "../lib/posture";
import { useAuth } from "../lib/auth";

export default function Dashboard({ onRequireAuth }: { onRequireAuth: () => void }) {
  const { user } = useAuth();
  const [data, setData] = useState<DashboardData | null>(null);
  const [riskConfig, setRiskConfig] = useState<RiskConfig | null>(null);
  const [mode, setMode] = useState<"git" | "path">("git");
  const [scanInput, setScanInput] = useState("");
  const [repoToken, setRepoToken] = useState("");
  const [scanning, setScanning] = useState(false);
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);

  const load = () => getDashboard().then(setData);
  useEffect(() => {
    load();
  }, [user]);
  useEffect(() => {
    getRiskConfig().then(setRiskConfig).catch(() => {});
  }, []);

  const doScan = async () => {
    const value = scanInput.trim();
    if (!value) return;
    if (!user) {
      onRequireAuth();
      return;
    }
    setScanning(true);
    setMsg(null);
    try {
      const r =
        mode === "git" ? await runGitScan(value, repoToken.trim() || undefined) : await runScan(value);
      const where = "repo" in r ? (r as any).repo : value;
      setMsg({
        ok: true,
        text: `Scanned ${r.job.filesScanned} files from ${where} in ${r.job.durationMs}ms — ${r.assetCount} quantum-vulnerable assets found.`,
      });
      await load();
    } catch (e: any) {
      setMsg({ ok: false, text: e?.response?.data?.error ?? "Scan failed." });
    } finally {
      setScanning(false);
    }
  };

  if (!data) return <div className="text-slate-400">Loading…</div>;

  const posture = computePosture(data);
  const familyData = Object.entries(data.byFamily).map(([name, value]) => ({ name, value }));
  const priorityData = (["critical", "high", "medium", "low"] as const).map((p) => ({
    name: p,
    value: data.byPriority[p] ?? 0,
  }));

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Cryptographic Posture</h1>
          <p className="text-sm text-slate-400">
            {data.lastScan
              ? `Last scan: ${data.lastScan.filesScanned} files in ${data.lastScan.durationMs}ms`
              : "No scans yet"}
          </p>
        </div>
        <div className="flex flex-col gap-2">
          <div className="flex overflow-hidden rounded-lg border border-slate-700 text-xs font-semibold">
            <button
              onClick={() => setMode("git")}
              className={`px-3 py-1.5 transition ${mode === "git" ? "bg-indigo-500 text-white" : "bg-slate-900 text-slate-400 hover:text-slate-200"}`}
            >
              Git Repo
            </button>
            <button
              onClick={() => setMode("path")}
              className={`px-3 py-1.5 transition ${mode === "path" ? "bg-indigo-500 text-white" : "bg-slate-900 text-slate-400 hover:text-slate-200"}`}
            >
              Local Path
            </button>
          </div>
          <div className="flex items-center gap-2">
            <input
              value={scanInput}
              onChange={(e) => setScanInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && doScan()}
              placeholder={mode === "git" ? "owner/repo or https://github.com/…" : "Absolute path to scan…"}
              className="w-full sm:w-80 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:border-indigo-500 focus:outline-none"
            />
            <button
              onClick={doScan}
              disabled={scanning}
              className="shrink-0 rounded-lg bg-indigo-500 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-400 disabled:opacity-50"
            >
              {scanning ? "Scanning…" : "Run Scan"}
            </button>
          </div>
          {mode === "git" && user && (
            <input
              value={repoToken}
              onChange={(e) => setRepoToken(e.target.value)}
              type="password"
              placeholder="Access token (optional — for private repos)"
              className="w-full sm:w-80 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-1.5 text-xs text-slate-300 placeholder:text-slate-600 focus:border-indigo-500 focus:outline-none"
            />
          )}
        </div>
      </header>

      {msg && (
        <div
          className={`rounded-lg border px-4 py-2 text-sm ${
            msg.ok
              ? "border-indigo-500/40 bg-indigo-500/10 text-indigo-200"
              : "border-rose-500/40 bg-rose-500/10 text-rose-200"
          }`}
        >
          {msg.text}
        </div>
      )}

      {data.delta?.hasPrevious && (data.delta.newFindings > 0 || data.delta.removedFindings > 0) && (
        <div
          className={`flex flex-wrap items-center gap-x-4 gap-y-1 rounded-lg border px-4 py-2 text-sm ${
            data.delta.newFindings > 0
              ? "border-amber-500/40 bg-amber-500/10 text-amber-200"
              : "border-emerald-500/40 bg-emerald-500/10 text-emerald-200"
          }`}
        >
          <span className="font-semibold uppercase tracking-wider text-xs opacity-80">Since previous scan</span>
          <span>
            <span className="font-bold">+{data.delta.newFindings}</span> new finding
            {data.delta.newFindings === 1 ? "" : "s"}
          </span>
          <span>
            <span className="font-bold">−{data.delta.removedFindings}</span> removed
          </span>
        </div>
      )}

      <Card className="p-5">
        <div className="flex items-center gap-5">
          <div
            className="flex h-20 w-20 shrink-0 items-center justify-center rounded-2xl text-4xl font-black"
            style={{ color: posture.color, border: `2px solid ${posture.color}`, background: `${posture.color}1a` }}
          >
            {posture.grade}
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-baseline gap-x-2">
              <h2 className="text-lg font-bold text-white">Quantum Posture: {posture.label}</h2>
              <span className="text-sm font-semibold" style={{ color: posture.color }}>
                {posture.score}/100
              </span>
            </div>
            <p className="mt-1 text-sm text-slate-400">{posture.narrative}</p>
            <div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-800">
              <div className="h-full rounded-full" style={{ width: `${posture.score}%`, background: posture.color }} />
            </div>
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-5">
        <StatCard label="Crypto Assets" value={data.totalAssets} accent="#818cf8" />
        <StatCard
          label="Quantum-Vulnerable"
          value={data.quantumVulnerable}
          sub={`${Math.round((data.quantumVulnerable / Math.max(data.totalAssets, 1)) * 100)}% of inventory`}
          accent="#f43f5e"
        />
        <StatCard
          label="Possible Mentions"
          value={data.possibleMentions}
          sub="low confidence · review"
          accent="#facc15"
        />
        <StatCard
          label="Migration Effort"
          value={`${data.remainingEffortDays}d`}
          sub={`remaining of ${data.migrationEffortDays}d total · actionable findings`}
          accent="#22d3ee"
        />
        <StatCard
          label="Avg Compliance"
          value={`${data.avgCompliancePct}%`}
          sub={`across ${data.frameworks.length} frameworks`}
          accent={data.avgCompliancePct >= 60 ? "#34d399" : "#facc15"}
        />
      </div>

      <Card className="p-5">
        <div className="mb-3 flex items-end justify-between">
          <h2 className="text-sm font-semibold text-slate-300">Migration Progress</h2>
          <span className="text-sm font-semibold text-emerald-300">{data.migrationProgressPct}% resolved</span>
        </div>
        <div className="flex h-3 overflow-hidden rounded-full bg-slate-800">
          {(["migrated", "accepted", "in_progress", "open"] as AssetStatus[]).map((s) => {
            const count = data.byStatus?.[s] ?? 0;
            const pct = data.totalAssets ? (count / data.totalAssets) * 100 : 0;
            if (pct === 0) return null;
            return (
              <div
                key={s}
                style={{ width: `${pct}%`, background: ASSET_STATUS_META[s].color }}
                title={`${ASSET_STATUS_META[s].label}: ${count}`}
              />
            );
          })}
        </div>
        <div className="mt-3 flex flex-wrap gap-4">
          {(["open", "in_progress", "migrated", "accepted"] as AssetStatus[]).map((s) => (
            <span key={s} className="flex items-center gap-1.5 text-xs text-slate-400">
              <span className="h-2.5 w-2.5 rounded-sm" style={{ background: ASSET_STATUS_META[s].color }} />
              {ASSET_STATUS_META[s].label}
              <span className="font-semibold text-slate-200">{data.byStatus?.[s] ?? 0}</span>
            </span>
          ))}
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="min-w-0 p-5">
          <h2 className="mb-3 text-sm font-semibold text-slate-300">Assets by Algorithm Family</h2>
          <ResponsiveContainer width="100%" height={220} minWidth={0}>
            <PieChart>
              <Pie data={familyData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={85} paddingAngle={2}>
                {familyData.map((d) => (
                  <Cell key={d.name} fill={FAMILY_COLOR[d.name] ?? "#64748b"} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} />
            </PieChart>
          </ResponsiveContainer>
          <div className="mt-2 flex flex-wrap gap-2">
            {familyData.map((d) => (
              <span key={d.name} className="flex items-center gap-1.5 text-xs text-slate-400">
                <span className="h-2.5 w-2.5 rounded-sm" style={{ background: FAMILY_COLOR[d.name] ?? "#64748b" }} />
                {d.name} ({d.value})
              </span>
            ))}
          </div>
        </Card>

        <Card className="min-w-0 p-5">
          <h2 className="mb-3 text-sm font-semibold text-slate-300">Risk Priority Distribution</h2>
          <div className="min-h-[220px] w-full">
            <ResponsiveContainer width="100%" height={220} minWidth={0}>
              <BarChart data={priorityData}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip cursor={{ fill: "#1e293b55" }} contentStyle={tooltipStyle} />
                <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                  {priorityData.map((d) => (
                    <Cell key={d.name} fill={SEVERITY_COLOR[d.name as keyof typeof SEVERITY_COLOR]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card className="p-5">
          <h2 className="mb-3 text-sm font-semibold text-slate-300">Compliance Frameworks</h2>
          <div className="space-y-4">
            {data.frameworks.map((f) => (
              <div key={f.framework}>
                <div className="mb-1 flex items-center justify-between">
                  <span className="text-sm font-medium text-slate-200">{f.framework}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-400">{f.scorePct}%</span>
                    <StatusBadge status={f.status} />
                  </div>
                </div>
                <div className="h-2 overflow-hidden rounded-full bg-slate-800">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${f.scorePct}%`,
                      background: f.scorePct >= 60 ? "#34d399" : f.scorePct >= 40 ? "#facc15" : "#f43f5e",
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {riskConfig && (
        <Card className="p-5">
          <div className="mb-1 flex items-end justify-between">
            <h2 className="text-sm font-semibold text-slate-300">Risk Model</h2>
            <span className="text-xs text-slate-500">5-factor weighted · transparent · tunable</span>
          </div>
          <p className="mb-3 text-xs text-slate-500">
            How each asset's 0–100 risk score is weighted. Calibrate per deployment via{" "}
            <code className="text-slate-400">QV_RISK_WEIGHTS</code>.
          </p>
          <div className="grid gap-2.5 sm:grid-cols-2">
            {Object.entries(riskConfig.weights)
              .sort((a, b) => b[1] - a[1])
              .map(([k, w]) => (
                <div key={k} title={riskConfig.factors[k]}>
                  <div className="mb-0.5 flex items-center justify-between text-xs">
                    <span className="text-slate-300">{FACTOR_LABEL[k] ?? k}</span>
                    <span className="font-semibold text-slate-200">{Math.round(w * 100)}%</span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-slate-800">
                    <div className="h-full rounded-full bg-indigo-400" style={{ width: `${Math.round(w * 100)}%` }} />
                  </div>
                </div>
              ))}
          </div>
        </Card>
      )}
    </div>
  );
}

const FACTOR_LABEL: Record<string, string> = {
  dataSensitivity: "Data sensitivity",
  retentionExposure: "Retention exposure",
  hndlExposure: "Harvest-now-decrypt-later",
  complianceImpact: "Compliance impact",
  businessImpact: "Business impact",
};

const tooltipStyle = {
  background: "#0f172a",
  border: "1px solid #1e293b",
  borderRadius: 8,
  color: "#e2e8f0",
  fontSize: 12,
};
