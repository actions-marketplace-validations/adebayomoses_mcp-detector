import { describe, expect, it } from "vitest";
import type { ScanResult } from "../../src/core/types.js";
import { renderSarif } from "../../src/reporting/sarif.js";
import { validateFormat } from "../../src/cli/shared.js";

const result: ScanResult = {
  tool: "mcp-detector",
  version: "0.1.0",
  target: "node server.mjs",
  server: { name: "example", version: "1.0.0" },
  status: "connected",
  counts: { tools: 1, resources: 0, prompts: 0 },
  score: 70,
  grade: "Fair",
  scores: { protocol: 100, security: 60, tools: 80, schema: 80, performance: 80, quality: 80 },
  summary: { critical: 1, high: 1, medium: 1, low: 1, info: 1 },
  timings: {},
  findings: [
    { rule: "MCP-005", name: "Tool poisoning indicator", severity: "critical", category: "security", tool: "search_files", message: "Suspicious instruction text", why: "May manipulate an agent.", recommendation: "Review the tool description." },
    { rule: "MCP-012", name: "Dangerous shell operation", severity: "high", category: "security", tool: "run_command", message: "Potentially dangerous command", why: "Could execute unintended commands.", recommendation: "Restrict command execution." },
    { rule: "MCP-004", name: "Example medium finding", severity: "medium", category: "quality", tool: "lookup", message: "A medium issue", why: "It can affect reliability.", recommendation: "Validate the input." },
    { rule: "MCP-900", name: "Example low finding", severity: "low", category: "quality", tool: "lookup", message: "A low issue", why: "Minor issue.", recommendation: "Consider improving it." },
    { rule: "MCP-901", name: "Example info finding", severity: "info", category: "quality", message: "Informational note", why: "Provides context.", recommendation: "No action required." },
  ],
  disclaimer: "Findings are indicators, not proof of exploitability.",
};

describe("SARIF reporting", () => {
  it("emits SARIF 2.1.0 with rules referenced by every result", () => {
    const sarif = JSON.parse(renderSarif(result));
    expect(sarif.$schema).toContain("sarif-2.1.0");
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].tool.driver.name).toBe("MCP Detector");
    const ruleIds = sarif.runs[0].tool.driver.rules.map((rule: { id: string }) => rule.id);
    expect(new Set(ruleIds).size).toBe(ruleIds.length);
    expect(sarif.runs[0].results.every((item: { ruleId: string }) => ruleIds.includes(item.ruleId))).toBe(true);
  });

  it("maps severities to GitHub SARIF levels and uses logical tool locations", () => {
    const sarif = JSON.parse(renderSarif(result));
    expect(sarif.runs[0].results.map((item: { level: string }) => item.level)).toEqual(["error", "error", "warning", "note", "note"]);
    expect(sarif.runs[0].results[0].locations[0].logicalLocations[0]).toEqual({ name: "search_files", kind: "function" });
    expect(sarif.runs[0].results[0].locations[0].physicalLocation).toEqual({ artifactLocation: { uri: "package.json" }, region: { startLine: 1 } });
    expect(sarif.runs[0].results[0].partialFingerprints["mcp-detector/rule-tool"]).toBe("MCP-005:search_files");
    expect(sarif.runs[0].results[4].locations[0].physicalLocation.artifactLocation.uri).toBe("package.json");
    const securityRule = sarif.runs[0].tool.driver.rules.find((rule: { id: string }) => rule.id === "MCP-005");
    expect(securityRule.shortDescription.text).toBe("Tool poisoning indicator");
    expect(securityRule.properties.tags).toEqual(["security"]);
    expect(securityRule.properties["security-severity"]).toBe("9.5");
    const qualityRule = sarif.runs[0].tool.driver.rules.find((rule: { id: string }) => rule.id === "MCP-004");
    expect(qualityRule.properties.tags).toBeUndefined();
    expect(qualityRule.properties["security-severity"]).toBeUndefined();
    expect(securityRule.help.text).toBeTruthy();
  });

  it("accepts a custom file anchor", () => {
    const sarif = JSON.parse(renderSarif(result, "src/index.ts"));
    expect(sarif.runs[0].results[0].locations[0].physicalLocation).toEqual({ artifactLocation: { uri: "src/index.ts" }, region: { startLine: 1 } });
  });

  it("accepts sarif as a report format", () => {
    expect(validateFormat("sarif")).toBe("sarif");
  });
});
