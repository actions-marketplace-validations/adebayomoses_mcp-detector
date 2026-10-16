import pc from "picocolors";
import { CATEGORIES, type Category, type ScanResult, type Severity } from "../core/types.js";
import { SEVERITY_ICON, SEVERITY_LABEL } from "./severity.js";
import { uniqueRecommendations } from "./recommendations.js";
import { renderHtmlReport } from "./html.js";
import { renderSarif } from "./sarif.js";

export type ReportFormat = "terminal" | "json" | "markdown" | "html" | "sarif";

export interface RenderOptions {
  verbose?: boolean;
  color?: boolean;
  sarifLocation?: string;
}

const CATEGORY_LABEL: Record<Category, string> = {
  protocol: "Protocol",
  security: "Security",
  tools: "Tools",
  schema: "Schema",
  performance: "Performance",
  quality: "Quality",
};

function scoreMark(score: number): string {
  return score >= 80 ? "✓" : score >= 60 ? "⚠" : "✗";
}

function ms(n?: number): string {
  if (n === undefined) return "n/a";
  return n >= 1000 ? `${(n / 1000).toFixed(1)} sec` : `${n} ms`;
}

export function renderReport(result: ScanResult, format: ReportFormat, opts: RenderOptions = {}): string {
  switch (format) {
    case "json":
      return JSON.stringify(toJson(result), null, 2);
    case "markdown":
      return renderMarkdown(result);
    case "html":
      return renderHtmlReport(result);
    case "sarif":
      return renderSarif(result, opts.sarifLocation);
    default:
      return renderTerminal(result, opts);
  }
}

/** JSON shape for CI/integrations. Adds a `status` field derived from the score. */
export function toJson(r: ScanResult) {
  return {
    ...r,
    status: r.status === "failed" ? "failed" : r.score >= 80 ? "ok" : r.score >= 60 ? "warning" : "critical",
    connection: r.status,
  };
}

function renderTerminal(r: ScanResult, opts: RenderOptions): string {
  const c = pc.createColors(opts.color ?? pc.isColorSupported);
  const L: string[] = [];
  L.push(c.bold("MCP DETECTOR"));
  L.push("━".repeat(44));
  L.push("");
  const name = r.server?.name ? `${r.server.name}${r.server.version ? " v" + r.server.version : ""}` : r.target;
  L.push(`Server: ${name}`);
  L.push(`Target: ${c.dim(r.target)}`);
  L.push(`Status: ${r.status === "connected" ? c.green("CONNECTED") : c.red("FAILED")}`);
  if (r.protocolVersion) L.push(`Protocol: ${r.protocolVersion}`);
  L.push("");
  const colorScore = r.score >= 80 ? c.green : r.score >= 60 ? c.yellow : c.red;
  L.push(`${c.bold("Health Score:")} ${colorScore(c.bold(`${r.score}/100`))}  (${r.grade})`);
  L.push("");

  if (r.status === "connected") {
    L.push(`Tools: ${r.counts.tools}   Resources: ${r.counts.resources}   Prompts: ${r.counts.prompts}`);
    L.push("");
    for (const cat of CATEGORIES) {
      const s = r.scores[cat];
      const mark = scoreMark(s);
      const col = s >= 80 ? c.green : s >= 60 ? c.yellow : c.red;
      L.push(`${col(mark)} ${CATEGORY_LABEL[cat].padEnd(12)} ${String(s).padStart(3)}`);
    }
    L.push("");
    L.push(c.bold("Security"));
    const sec = r.findings.filter((f) => f.category === "security");
    const count = (sev: Severity) => sec.filter((f) => f.severity === sev).length;
    if (!sec.length) L.push(`${c.green("✓")} No security findings`);
    else {
      for (const sev of ["critical", "high", "medium", "low"] as Severity[])
        if (count(sev)) L.push(`${SEVERITY_ICON[sev]} ${count(sev)} ${SEVERITY_LABEL[sev][0]}${SEVERITY_LABEL[sev].slice(1).toLowerCase()}`);
    }
    L.push("");
    L.push(c.bold("Performance"));
    L.push(`Connection + init: ${ms(r.timings.connectMs)}`);
    L.push(`Tool discovery:    ${ms(r.timings.discoveryMs)}`);
    if (r.timings.avgToolMs !== undefined) {
      L.push(`Average tool:      ${ms(r.timings.avgToolMs)}`);
      L.push(`Timeout rate:      ${((r.timings.timeoutRate ?? 0) * 100).toFixed(1)}%`);
      L.push(`Error rate:        ${((r.timings.errorRate ?? 0) * 100).toFixed(1)}%`);
    } else {
      L.push(c.dim("Tool calls not measured (passive scan). Use --active to time read-only tools."));
    }
    L.push("");
  }

  if (r.findings.length) {
    L.push(c.bold("Findings:"));
    L.push("");
    for (const f of r.findings) {
      const colr = f.severity === "critical" ? c.red : f.severity === "high" ? c.magenta : f.severity === "medium" ? c.yellow : c.cyan;
      L.push(`${SEVERITY_ICON[f.severity]} ${colr(c.bold(f.rule))} ${c.bold(f.name)}${f.tool ? c.dim(`  [${f.tool}]`) : ""}`);
      L.push(`   ${f.message}`);
      if (f.evidence) L.push(c.dim(`   evidence: ${f.evidence}`));
      for (const d of f.details ?? []) L.push(c.dim(`   • ${d}`));
      if (opts.verbose) {
        L.push(c.dim(`   why: ${f.why}`));
        L.push(`   ${c.green("fix:")} ${f.recommendation}`);
      }
      L.push("");
    }
    if (!opts.verbose) {
      L.push(c.dim("Run with --verbose for explanations and remediation, or `mcp-detector rules <ID>` for rule docs."));
      L.push("");
    }
  } else if (r.status === "connected") {
    L.push(c.green("No findings."));
    L.push("");
  }
  L.push(`${r.findings.length} finding${r.findings.length === 1 ? "" : "s"}` + summaryTail(r));
  L.push("");
  L.push(c.dim(r.disclaimer));
  return L.join("\n");
}

function summaryTail(r: ScanResult): string {
  const parts = (["critical", "high", "medium", "low", "info"] as Severity[])
    .filter((s) => r.summary[s])
    .map((s) => `${r.summary[s]} ${s}`);
  return parts.length ? ` (${parts.join(", ")})` : "";
}

function renderMarkdown(r: ScanResult): string {
  const L: string[] = [];
  L.push("# MCP Detector Report", "");
  const name = r.server?.name ? `${r.server.name}${r.server.version ? " v" + r.server.version : ""}` : r.target;
  L.push(`**Server:** \`${name}\`  `);
  L.push(`**Status:** ${r.status === "connected" ? "connected" : "failed to connect"}  `);
  if (r.protocolVersion) L.push(`**Protocol:** ${r.protocolVersion}  `);
  L.push(`**Tools / Resources / Prompts:** ${r.counts.tools} / ${r.counts.resources} / ${r.counts.prompts}`, "");
  L.push(`## Score: ${r.score}/100 (${r.grade})`, "");
  L.push("| Category | Score |", "|---|---|");
  for (const cat of CATEGORIES) L.push(`| ${CATEGORY_LABEL[cat]} | ${r.scores[cat]} |`);
  L.push("");
  L.push("## Performance", "");
  L.push(`- Connection + initialization: ${ms(r.timings.connectMs)}`);
  L.push(`- Tool discovery: ${ms(r.timings.discoveryMs)}`);
  if (r.timings.avgToolMs !== undefined) {
    L.push(`- Average tool call: ${ms(r.timings.avgToolMs)}`);
    L.push(`- Timeout rate: ${((r.timings.timeoutRate ?? 0) * 100).toFixed(1)}%`);
  } else L.push("- Tool calls: not measured (passive scan)");
  L.push("");
  L.push(`## Findings (${r.findings.length})`, "");
  if (!r.findings.length) L.push("No findings.", "");
  for (const f of r.findings) {
    L.push(`- ${SEVERITY_ICON[f.severity]} **${f.rule} ${f.name}**${f.tool ? ` — \`${f.tool}\`` : ""} _(${f.severity})_`);
    L.push(`  - ${f.message}`);
    if (f.evidence) L.push(`  - Evidence: ${f.evidence.replace(/\n/g, " ")}`);
    for (const d of f.details ?? []) L.push(`  - ${d.replace(/\n/g, " ")}`);
  }
  if (r.findings.length) {
    L.push("", "## Recommendations", "");
    for (const rec of uniqueRecommendations(r.findings))
      L.push(`- **${rec.rule} ${rec.name}** (${rec.count}×): ${rec.recommendation}`);
  }
  L.push("", "---", `_${r.disclaimer}_`, `_Generated by mcp-detector ${r.version}._`);
  return L.join("\n");
}
