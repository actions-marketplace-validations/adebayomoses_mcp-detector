import { isAbsolute, relative } from "node:path";
import type { Finding, ScanResult, Severity } from "../core/types.js";
import { allRules } from "../rules/index.js";

const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.0",
  low: "2.0",
  info: "0.0",
};

function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

function fileUri(location: string): string {
  const path = (isAbsolute(location) ? relative(process.cwd(), location) : location).replace(/\\/g, "/");
  return encodeURI(path).replace(/#/g, "%23").replace(/\?/g, "%3F");
}

export function renderSarif(result: ScanResult, location = "package.json"): string {
  const findingsByRule = new Map<string, Finding>();
  for (const finding of result.findings) {
    if (!findingsByRule.has(finding.rule)) findingsByRule.set(finding.rule, finding);
  }
  const rules = [...findingsByRule.values()].map((finding) => {
    const registered = allRules().find((rule) => rule.id === finding.rule);
    const severity = registered?.severity ?? finding.severity;
    return {
      id: finding.rule,
      name: registered?.name ?? finding.name,
      shortDescription: { text: registered?.name ?? finding.name },
      fullDescription: { text: registered?.why ?? finding.why },
      help: { text: registered?.recommendation ?? finding.recommendation },
      defaultConfiguration: { level: sarifLevel(severity) },
      properties: {
        category: finding.category,
        ...(finding.category === "security"
          ? { tags: ["security"], "security-severity": SECURITY_SEVERITY[severity] }
          : {}),
      },
    };
  }).sort((a, b) => a.id.localeCompare(b.id));
  const results = result.findings.map((finding) => ({
    ruleId: finding.rule,
    level: sarifLevel(finding.severity),
    message: { text: finding.message },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: fileUri(location) },
        region: { startLine: 1 },
      },
      ...(finding.tool ? { logicalLocations: [{ name: finding.tool, kind: "function" }] } : {}),
    }],
    partialFingerprints: {
      "mcp-detector/rule-tool": `${finding.rule}:${finding.tool ?? ""}`,
    },
    properties: {
      severity: finding.severity,
      category: finding.category,
      ...(finding.evidence ? { evidence: finding.evidence } : {}),
      ...(finding.details?.length ? { details: finding.details } : {}),
      recommendation: finding.recommendation,
    },
  }));
  return JSON.stringify({
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "MCP Detector",
          informationUri: "https://github.com/adebayomoses/mcp-detector",
          rules,
        },
      },
      results,
    }],
  }, null, 2);
}
