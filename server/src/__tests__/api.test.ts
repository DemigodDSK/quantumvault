import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Isolate the database before importing the app (which transitively opens it).
const dbDir = mkdtempSync(join(tmpdir(), "qv-api-db-"));
process.env.QV_DB_PATH = join(dbDir, "test.db");
process.env.QV_LOG = "off"; // keep test output clean of access logs

const { createApp } = await import("../app.js");

let server: Server;
let base: string;
const srcDir = mkdtempSync(join(tmpdir(), "qv-api-src-"));

before(async () => {
  writeFileSync(
    join(srcDir, "app.ts"),
    ["generateKeyPairSync('rsa', { modulusLength: 2048 });", "createDiffieHellman(2048);"].join("\n"),
  );
  server = createApp().listen(0);
  await once(server, "listening");
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => {
  server.close();
  rmSync(dbDir, { recursive: true, force: true });
  rmSync(srcDir, { recursive: true, force: true });
});

const json = (path: string, init?: RequestInit) => fetch(base + path, init);
const authed = (token: string, extra: RequestInit = {}): RequestInit => ({
  ...extra,
  headers: { "content-type": "application/json", authorization: `Bearer ${token}`, ...(extra.headers ?? {}) },
});

async function signup(email: string, orgName: string): Promise<string> {
  const r = await json("/api/auth/signup", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password: "hunter2pw12", orgName }),
  });
  assert.equal(r.status, 201);
  return (await r.json()).token as string;
}

test("health reports ok, the running version, and the pattern count", async () => {
  const { VERSION } = await import("../version.js");
  const r = await json("/api/health");
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.equal(body.status, "ok");
  assert.equal(body.version, VERSION, "health must report the running build version");
  assert.equal(body.patterns, 59);
});

test("risk/config exposes the active weights and factor descriptions", async () => {
  const r = await json("/api/risk/config");
  assert.equal(r.status, 200);
  const body = await r.json();
  const sum = Object.values(body.weights as Record<string, number>).reduce((a, b) => a + b, 0);
  assert.ok(Math.abs(sum - 1) < 1e-9, `weights should sum to 1.0, got ${sum}`);
  assert.ok(body.factors.hndlExposure.length > 0);
});

test("openapi.json is served and well-formed", async () => {
  const r = await json("/api/openapi.json");
  assert.equal(r.status, 200);
  assert.match(r.headers.get("content-type") ?? "", /application\/json/);
  const doc = await r.json();
  assert.equal(doc.openapi, "3.1.0");
  assert.ok(doc.paths["/scans"]);
});

test("auth is required for scanning and status changes", async () => {
  const noTok = await json("/api/scans", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ target: srcDir }),
  });
  assert.equal(noTok.status, 401);

  const patch = await json("/api/assets/whatever/status", {
    method: "PATCH",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ status: "migrated" }),
  });
  assert.equal(patch.status, 401);
});

test("scan → list → patch status → CSV export, all org-scoped", async () => {
  const tokenA = await signup("a@acme.test", "Acme");

  // Scan a temp source tree.
  const scan = await json("/api/scans", authed(tokenA, { method: "POST", body: JSON.stringify({ target: srcDir }) }));
  assert.equal(scan.status, 201);
  assert.ok((await scan.json()).assetCount >= 2);

  // List assets for org A.
  const assets = await (await json("/api/assets", authed(tokenA))).json();
  assert.ok(Array.isArray(assets) && assets.length >= 2);
  const assetId = assets[0].id as string;

  // Invalid status rejected.
  const bad = await json(`/api/assets/${assetId}/status`, authed(tokenA, { method: "PATCH", body: JSON.stringify({ status: "nope" }) }));
  assert.equal(bad.status, 400);

  // Valid status accepted and reflected.
  const ok = await json(`/api/assets/${assetId}/status`, authed(tokenA, { method: "PATCH", body: JSON.stringify({ status: "migrated" }) }));
  assert.equal(ok.status, 200);
  assert.equal((await ok.json()).status, "migrated");

  // Dashboard reflects one migrated asset.
  const dash = await (await json("/api/dashboard", authed(tokenA))).json();
  assert.equal(dash.byStatus.migrated, 1);
  assert.ok(dash.migrationProgressPct > 0);

  // CSV export has the right content type and a header row.
  const csv = await json("/api/assets/export.csv", authed(tokenA));
  assert.equal(csv.status, 200);
  assert.match(csv.headers.get("content-type") ?? "", /text\/csv/);
  assert.match(await csv.text(), /^file,line,family,/);

  // CBOM export is a valid CycloneDX 1.6 document for org A's scan.
  const cbom = await json("/api/cbom.json", authed(tokenA));
  assert.equal(cbom.status, 200);
  assert.match(cbom.headers.get("content-type") ?? "", /cyclonedx\+json/);
  const cbomBody = await cbom.json();
  assert.equal(cbomBody.bomFormat, "CycloneDX");
  assert.equal(cbomBody.specVersion, "1.6");
  assert.ok(cbomBody.components.length >= 2);
  assert.equal(cbomBody.components[0].type, "cryptographic-asset");

  // SARIF export is a valid 2.1.0 log for org A's scan.
  const sarif = await json("/api/sarif.json", authed(tokenA));
  assert.equal(sarif.status, 200);
  assert.match(sarif.headers.get("content-type") ?? "", /sarif\+json/);
  const sarifBody = await sarif.json();
  assert.equal(sarifBody.version, "2.1.0");
  assert.equal(sarifBody.runs[0].tool.driver.name, "UniQueS");
  assert.ok(sarifBody.runs[0].results.length >= 2);

  // Org B is isolated: sees no assets and cannot mutate org A's asset.
  const tokenB = await signup("b@beta.test", "Beta");
  const bAssets = await (await json("/api/assets", authed(tokenB))).json();
  assert.equal(bAssets.length, 0);
  const cross = await json(`/api/assets/${assetId}/status`, authed(tokenB, { method: "PATCH", body: JSON.stringify({ status: "open" }) }));
  assert.equal(cross.status, 404);
});

test("unknown asset id returns 404", async () => {
  const r = await json("/api/assets/does-not-exist");
  assert.equal(r.status, 404);
});

test("assessment report is generated from a scan as JSON and branded HTML, org-scoped", async () => {
  const token = await signup("assess@acme.test", "Assessment Co");

  // A brand-new org has no scan yet -> 404 with a helpful message.
  const before = await json("/api/assessment/report.json", authed(token));
  assert.equal(before.status, 404);

  // After a scan, the structured model is populated from real findings.
  const scan = await json("/api/scans", authed(token, { method: "POST", body: JSON.stringify({ target: srcDir }) }));
  assert.equal(scan.status, 201);

  const jsonRes = await json("/api/assessment/report.json", authed(token));
  assert.equal(jsonRes.status, 200);
  const model = await jsonRes.json();
  assert.equal(model.orgName, "Assessment Co");
  assert.ok(model.totals.totalAssets >= 2);
  assert.ok(["A", "B", "C", "D", "F"].includes(model.posture.grade));
  assert.ok(Array.isArray(model.inventory) && model.inventory.length >= 1);
  assert.equal(model.priority.length, 4);
  assert.equal(model.roadmap.length, 3);

  // The HTML deliverable is branded, escaped, print-ready, and carries the org name.
  const htmlRes = await json("/api/assessment/report.html", authed(token));
  assert.equal(htmlRes.status, 200);
  assert.match(htmlRes.headers.get("content-type") ?? "", /text\/html/);
  const html = await htmlRes.text();
  assert.ok(html.includes("Quantum Readiness"));
  assert.ok(html.includes("Assessment Co"));
  assert.ok(html.includes("@media print"));

  // Org isolation: a different org with no scan still 404s (can't see this org's data).
  const other = await signup("empty@beta.test", "Empty Co");
  const otherRes = await json("/api/assessment/report.json", authed(other));
  assert.equal(otherRes.status, 404);
});

test("responses carry baseline security headers", async () => {
  const r = await json("/api/health");
  assert.equal(r.headers.get("x-content-type-options"), "nosniff");
  assert.equal(r.headers.get("x-frame-options"), "DENY");
  assert.equal(r.headers.get("x-powered-by"), null);
});

test("CORS is enabled and reflects the default (allow-any) origin", async () => {
  const r = await json("/api/health", { headers: { origin: "http://dashboard.test" } });
  assert.equal(r.headers.get("access-control-allow-origin"), "*");
});

test("unmatched API routes return a JSON 404 envelope", async () => {
  const r = await json("/api/nope/not/a/route");
  assert.equal(r.status, 404);
  assert.match(r.headers.get("content-type") ?? "", /application\/json/);
  assert.equal((await r.json()).error, "not found");
});

test("malformed JSON bodies get a 400, not a 500", async () => {
  const r = await json("/api/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{ not valid json",
  });
  assert.equal(r.status, 400);
});

test("compliance framework lookup is case-insensitive (FedRAMP export works)", async () => {
  const token = await signup("fedramp@test.io", "FedRAMP Org");
  const scan = await json("/api/scans", authed(token, { method: "POST", body: JSON.stringify({ target: srcDir }) }));
  assert.equal(scan.status, 201);

  // "FedRAMP" is stored mixed-case; any casing of the path param must resolve to
  // it (SQLite "=" is case-sensitive, so a naive toUpperCase() 404s the report).
  for (const fw of ["FedRAMP", "fedramp", "FEDRAMP"]) {
    const r = await json(`/api/compliance/${fw}`, authed(token));
    assert.equal(r.status, 200, `GET /compliance/${fw} should be 200`);
    assert.equal((await r.json()).framework, "FedRAMP");
  }

  const expJson = await json("/api/compliance/fedramp/export.json", authed(token));
  assert.equal(expJson.status, 200);
  assert.match(expJson.headers.get("content-disposition") ?? "", /FedRAMP-compliance\.json/);

  const expHtml = await json("/api/compliance/FedRAMP/export.html", authed(token));
  assert.equal(expHtml.status, 200);
  assert.match(expHtml.headers.get("content-type") ?? "", /text\/html/);

  // An unknown framework still 404s.
  const unknown = await json("/api/compliance/NOTAFRAMEWORK", authed(token));
  assert.equal(unknown.status, 404);
});
