import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { example, runCli } from "../fixtures/run-cli.js";

const tmp = () => mkdtempSync(join(tmpdir(), "mcpd-e2e-"));
const secure = ["--", process.execPath, example("secure-server")];
const vulnerable = ["--", process.execPath, example("vulnerable-server")];

describe("CLI end to end", () => {
  it("scan prints a report and exits 0 for a clean server", () => {
    const r = runCli(["scan", "--fail-on", "medium", ...secure], { cwd: tmp() });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("Health Score: 100/100");
    expect(r.stdout).toContain("CONNECTED");
  }, 60_000);

  it("--fail-on high exits 1 and says why on stderr", () => {
    const r = runCli(["scan", "--fail-on", "high", ...vulnerable], { cwd: tmp() });
    expect(r.code).toBe(1);
    expect(r.stderr).toMatch(/MCP Detector failed: \d+ finding\(s\) at or above "high"/);
  }, 60_000);

  it("without --fail-on a risky server still exits 0", () => {
    expect(runCli(["scan", ...vulnerable], { cwd: tmp() }).code).toBe(0);
  }, 60_000);

  it("--format json emits valid, stable JSON only on stdout", () => {
    const r = runCli(["scan", "--format", "json", ...vulnerable], { cwd: tmp() });
    const j = JSON.parse(r.stdout);
    expect(j.tool).toBe("mcp-detector");
    expect(j.score).toBeLessThan(70);
    expect(j.status).toMatch(/warning|critical/);
    expect(j.findings.every((f: any) => f.rule && f.severity && f.recommendation)).toBe(true);
    expect(JSON.stringify(j)).not.toContain("AKIAIOSFODNN7EXAMPLE"); // secrets are redacted
  }, 60_000);

  it("--format markdown writes a PR-ready report to a file", () => {
    const dir = tmp();
    const out = join(dir, "report.md");
    const r = runCli(["scan", "--format", "markdown", "--output", out, ...vulnerable], { cwd: dir });
    expect(r.code).toBe(0);
    const md = readFileSync(out, "utf8");
    expect(md).toContain("# MCP Detector Report");
    expect(md).toMatch(/## Score: \d+\/100/);
    expect(md).toContain("MCP-012");
    expect(md).toContain("## Recommendations");
    expect(md).not.toMatch(/\x1b\[/); // no ANSI codes in files
  }, 60_000);

  it("scan --format sarif -o writes a file-anchored SARIF report", () => {
    const dir = tmp();
    const out = join(dir, "mcp-report.sarif");
    writeFileSync(join(dir, "package.json"), "{}");
    const r = runCli(["scan", "--format", "sarif", "-o", out, "--sarif-location", "package.json", ...vulnerable], { cwd: dir });
    expect(r.code).toBe(0);
    const sarif = JSON.parse(readFileSync(out, "utf8"));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);
    expect(sarif.runs[0].results.every((item: any) => item.locations[0].physicalLocation.artifactLocation.uri === "package.json")).toBe(true);
    expect(r.stderr).toContain("Report written to");
  }, 60_000);

  it("report re-renders the last scan and saved JSON files", () => {
    const dir = tmp();
    runCli(["scan", "--format", "json", "--output", join(dir, "r.json"), ...vulnerable], { cwd: dir });
    expect(existsSync(join(dir, ".mcp-detector", "last-scan.json"))).toBe(true);
    const md = runCli(["report"], { cwd: dir });
    expect(md.code).toBe(0);
    expect(md.stdout).toContain("# MCP Detector Report");
    const term = runCli(["report", "r.json", "--format", "terminal"], { cwd: dir });
    expect(term.stdout).toContain("MCP DETECTOR");
    const bad = runCli(["report", "missing.json"], { cwd: dir });
    expect(bad.code).toBe(2);
    expect(bad.stderr).toContain("No saved scan");
  }, 60_000);

  it("auto-discovers mcp-detector.yml: server block, fail_on, rule overrides", () => {
    const dir = tmp();
    writeFileSync(
      join(dir, "mcp-detector.yml"),
      [
        "server:",
        `  command: ${JSON.stringify(process.execPath)}`,
        `  args: [${JSON.stringify(example("vulnerable-server"))}]`,
        "severity:",
        "  fail_on: critical",
        "rules:",
        "  tool_poisoning: false",
        "  MCP-012: off",
        "  MCP-004: low",
      ].join("\n"),
    );
    const r = runCli(["scan", "--format", "json"], { cwd: dir });
    const j = JSON.parse(r.stdout);
    const ids = j.findings.map((f: any) => f.rule);
    expect(ids).not.toContain("MCP-005"); // group disabled
    expect(ids).not.toContain("MCP-012"); // rule disabled
    expect(j.findings.filter((f: any) => f.rule === "MCP-004").every((f: any) => f.severity === "low")).toBe(true);
    expect(r.code).toBe(0); // nothing critical is left, so fail_on: critical passes
  }, 60_000);

  it("--config selects a file and CLI flags override it", () => {
    const dir = tmp();
    writeFileSync(join(dir, "strict.yml"), "severity:\n  fail_on: low\n");
    expect(runCli(["scan", "--config", "strict.yml", ...secure], { cwd: dir }).code).toBe(0);
    const r = runCli(["scan", "--config", "strict.yml", "--fail-on", "none", ...vulnerable], { cwd: dir });
    expect(r.code).toBe(0);
  }, 60_000);

  it("an invalid config gives a clear usage error (exit 2)", () => {
    const dir = tmp();
    writeFileSync(join(dir, "mcp-detector.yml"), "severity:\n  fail_on: severe\n");
    const r = runCli(["scan", ...secure], { cwd: dir });
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('Invalid severity "severe"');
  }, 60_000);

  it("no target is a usage error that shows how to specify one", () => {
    const r = runCli(["scan"], { cwd: tmp() });
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("No MCP server specified");
  }, 60_000);

  it("an unreachable server exits 1 with a failed status", () => {
    const r = runCli(["scan", "--format", "json", "--", process.execPath, "no-such-file.mjs"], { cwd: tmp() });
    expect(r.code).toBe(1);
    expect(JSON.parse(r.stdout).connection).toBe("failed");
  }, 60_000);

  it("inspect, test, rules and init work", () => {
    const dir = tmp();
    const insp = runCli(["inspect", "--format", "json", ...vulnerable], { cwd: dir });
    const tools = JSON.parse(insp.stdout).tools;
    expect(tools.find((t: any) => t.name === "execute_command").capabilities).toContain("shell");
    const t = runCli(["test", ...secure], { cwd: dir });
    expect(t.code).toBe(0);
    expect(t.stdout).toContain("✓ Ping");
    expect(runCli(["rules", "MCP-012"]).stdout).toContain("Dangerous shell operation");
    expect(runCli(["rules", "MCP-999"]).code).toBe(2);
    expect(runCli(["init"], { cwd: dir }).code).toBe(0);
    expect(readFileSync(join(dir, "mcp-detector.yml"), "utf8")).toContain("fail_on");
    expect(runCli(["init"], { cwd: dir }).code).toBe(2); // refuses to overwrite
  }, 120_000);
});
