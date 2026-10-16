import pc from "picocolors";
import { existsSync, readFileSync } from "node:fs";
import { Command } from "commander";
import type { ScanResult } from "../../core/types.js";
import { renderReport } from "../../reporting/report-generator.js";
import { LAST_SCAN_PATH, validateFormat, writeOutput } from "../shared.js";

export function reportCommand(): Command {
  return new Command("report")
    .description("Render a saved scan (default: the most recent `scan`) as terminal, JSON, Markdown, HTML or SARIF output")
    .argument("[file]", "JSON result saved by `scan --format json -o <file>`", LAST_SCAN_PATH)
    .option("-f, --format <format>", "terminal | json | markdown | html | sarif", "markdown")
    .option("-o, --output <file>", "write the report to a file")
    .option("--verbose", "include explanations and remediation")
    .option("--no-color", "disable colored output")
    .action((file: string, opts: { format?: string; output?: string; verbose?: boolean; color?: boolean }) => {
      if (!existsSync(file)) throw new Error(`No saved scan at ${file}. Run \`mcp-detector scan\` first.`);
      let result: ScanResult;
      try {
        result = JSON.parse(readFileSync(file, "utf8"));
      } catch (e) {
        throw new Error(`Could not read ${file}: ${(e as Error).message}`);
      }
      if (result?.tool !== "mcp-detector" || !Array.isArray(result.findings))
        throw new Error(`${file} is not an MCP Detector result.`);
      writeOutput(
        renderReport(result, validateFormat(opts.format), { verbose: opts.verbose, color: opts.color !== false && !opts.output && pc.isColorSupported }),
        opts.output,
      );
    });
}
