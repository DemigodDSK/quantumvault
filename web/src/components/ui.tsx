import type { ReactNode } from "react";
import type { Severity, ComplianceStatus, AssetStatus } from "../lib/api";

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#facc15",
  low: "#38bdf8",
};

export const FAMILY_COLOR: Record<string, string> = {
  RSA: "#818cf8",
  ECC: "#22d3ee",
  DSA: "#c084fc",
  DH: "#2dd4bf",
  SymmetricLegacy: "#fb923c",
  HashLegacy: "#f472b6",
  Asymmetric: "#94a3b8",
  PQC: "#4ade80", // post-quantum inventory (safe) — green, not a warning color
};

export function SeverityBadge({ level }: { level: Severity }) {
  const color = SEVERITY_COLOR[level];
  return (
    <span
      className="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide"
      style={{ color, backgroundColor: `${color}1f`, border: `1px solid ${color}55` }}
    >
      {level}
    </span>
  );
}

const STATUS_META: Record<ComplianceStatus, { label: string; color: string }> = {
  pass: { label: "Pass", color: "#34d399" },
  gap: { label: "Partial", color: "#facc15" },
  fail: { label: "Fail", color: "#f43f5e" },
};

export function StatusBadge({ status }: { status: ComplianceStatus }) {
  const m = STATUS_META[status];
  return (
    <span
      className="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold"
      style={{ color: m.color, backgroundColor: `${m.color}1f`, border: `1px solid ${m.color}55` }}
    >
      {m.label}
    </span>
  );
}

export const ASSET_STATUS_META: Record<AssetStatus, { label: string; color: string }> = {
  open: { label: "Open", color: "#94a3b8" },
  in_progress: { label: "In Progress", color: "#facc15" },
  migrated: { label: "Migrated", color: "#34d399" },
  accepted: { label: "Accepted Risk", color: "#a78bfa" },
};

export function AssetStatusBadge({ status }: { status: AssetStatus }) {
  const m = ASSET_STATUS_META[status];
  return (
    <span
      className="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold"
      style={{ color: m.color, backgroundColor: `${m.color}1f`, border: `1px solid ${m.color}55` }}
    >
      {m.label}
    </span>
  );
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={`rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur ${className}`}
    >
      {children}
    </div>
  );
}

export function StatCard({
  label,
  value,
  sub,
  accent = "#818cf8",
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  accent?: string;
}) {
  return (
    <Card className="p-5">
      <div className="text-xs font-medium uppercase tracking-wider text-slate-400">{label}</div>
      <div className="mt-2 text-3xl font-bold" style={{ color: accent }}>
        {value}
      </div>
      {sub && <div className="mt-1 text-sm text-slate-400">{sub}</div>}
    </Card>
  );
}
