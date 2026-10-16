import pc from "picocolors";
import { Command } from "commander";
import { runScan } from "../../core/detector.js";
import { saveHistory } from "../../store/history.js";
import { renderReport } from "../../reporting/report-generator.js";
import { countAtOrAbove, exceedsThreshold } from "../../reporting/severity.js";
import {
  addOutputOptions,
  addTargetOptions,
  loadExtraRules,
  resolveConfig,
  saveLastScan,
  validateFormat,
  writeOutput,
  type CommonOptions,
} from "../shared.js";

export function scanCommand(): Command {
  const cmd = new Command("scan")
    .description("Connect to an MCP server and run all protocol, security, schema, quality and performance checks")
    .argument("[target...]", "server command (after `--`) or an http(s) URL")
    .option("--fail-on <severity>", "exit with code 1 if any finding is at or above: info|low|medium|high|critical")
    .option("--baseline <file>", "compare tool definitions against a pinned baseline (default: ./mcp-detector.lock.json if present)")
    .option("--no-baseline", "ignore any pinned baseline")
    .option("--active", "also call tools that look read-only, to measure latency and timeouts (off by default)")
    .option("--sarif-location <path>", "file anchor for SARIF results (default: package.json)", "package.json");
  addTargetOptions(cmd);
  addOutputOptions(cmd);
  cmd.action(async (target: string[], opts: CommonOptions) => {
    const format = validateFormat(opts.format);
    const { config } = resolveConfig(target, opts);
    await loadExtraRules(config, opts);
    const { result, snapshot, ruleErrors } = await runScan(config);
    saveLastScan(result);
    if (opts.history !== false) saveHistory(result);
    writeOutput(renderReport(result, format, { verbose: opts.verbose, color: opts.color !== false && !opts.output && pc.isColorSupported, sarifLocation: opts.sarifLocation }), opts.output);

    if (format === "terminal") {
      for (const e of ruleErrors) process.stderr.write(`warning: rule ${e.rule} failed to run: ${e.error}\n`);
      if (snapshot.activeMode && snapshot.skippedCalls.length)
        process.stderr.write(`note: skipped ${snapshot.skippedCalls.length} tool(s) in active mode (not recognised as read-only).\n`);
    }
    const threshold = config.severity.fail_on;
    if (exceedsThreshold(result.findings, threshold)) {
      if (threshold !== "none") {
        process.stderr.write(
          `\nMCP Detector failed: ${countAtOrAbove(result.findings, threshold)} finding(s) at or above "${threshold}" (score ${result.score}/100).\n`,
        );
      }
      process.exitCode = 1;
    } else if (result.status === "failed") process.exitCode = 1;
  });
  return cmd;
}
