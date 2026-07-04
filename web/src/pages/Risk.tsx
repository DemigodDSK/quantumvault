import { useEffect, useMemo, useState } from "react";
import { getAssets, type CryptoAsset } from "../lib/api";
import { Card, SeverityBadge, StatCard, SEVERITY_COLOR } from "../components/ui";

export default function Risk() {
  const [assets, setAssets] = useState<CryptoAsset[]>([]);

  useEffect(() => {
    getAssets().then(setAssets);
  }, []);

  const ranked = useMemo(
    () => [...assets].sort((a, b) => (b.risk?.score ?? 0) - (a.risk?.score ?? 0)),
    [assets],
  );

  const totalEffort = useMemo(
    () => assets.reduce((s, a) => s + (a.risk?.migrationEffortDays ?? 0), 0),
    [assets],
  );
  const critical = ranked.filter((a) => a.risk?.priority === "critical").length;
  const high = ranked.filter((a) => a.risk?.priority === "high").length;
  const avg = assets.length
    ? Math.round(assets.reduce((s, a) => s + (a.risk?.score ?? 0), 0) / assets.length)
    : 0;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold text-white">Risk Analysis</h1>
        <p className="text-sm text-slate-400">
          Transparent 5-factor scoring · prioritized migration roadmap
        </p>
      </header>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Mean Risk Score" value={avg} accent="#fb923c" />
        <StatCard label="Critical" value={critical} accent={SEVERITY_COLOR.critical} />
        <StatCard label="High" value={high} accent={SEVERITY_COLOR.high} />
        <StatCard label="Total Migration Effort" value={`${totalEffort}d`} accent="#22d3ee" />
      </div>

      <Card className="p-5">
        <h2 className="mb-1 text-sm font-semibold text-slate-300">Prioritized Migration Roadmap</h2>
        <p className="mb-4 text-xs text-slate-500">
          Highest-risk assets first. Sequence migration top-down to retire the most exposure soonest.
        </p>
        <ol className="space-y-3">
          {ranked.slice(0, 12).map((a, i) => (
            <li key={a.id} className="flex items-start gap-4">
              <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-slate-800 text-xs font-bold text-slate-300">
                {i + 1}
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-slate-200">{a.algorithm}</span>
                  {a.risk && <SeverityBadge level={a.risk.priority} />}
                  <span className="font-mono text-xs text-slate-500">{a.file}:{a.line}</span>
                </div>
                <p className="mt-0.5 text-sm text-slate-400">{a.risk?.recommendation}</p>
              </div>
              <div className="text-right">
                <div className="text-lg font-bold" style={{ color: SEVERITY_COLOR[a.risk?.priority ?? "low"] }}>
                  {a.risk?.score}
                </div>
                <div className="text-[11px] text-slate-500">~{a.risk?.migrationEffortDays}d</div>
              </div>
            </li>
          ))}
        </ol>
      </Card>
    </div>
  );
}
