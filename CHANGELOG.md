# Changelog

All notable changes are documented here. Format based on [Keep a Changelog](https://keepachangelog.com/); versions follow [SemVer](https://semver.org/).

## [0.1.0] - Unreleased

### Added
- SARIF 2.1.0 reports via `--format sarif`, with configurable GitHub Code Scanning file anchors and logical tool locations.
- CLI: `scan`, `inspect`, `test`, `report`, `rules`, `init`.
- Transports: stdio, Streamable HTTP (with SSE fallback).
- 32 detection rules (MCP-001 – MCP-032) across protocol, schema, security, tools, quality and performance.
- Health score (0–100) with per-category breakdown.
- Terminal, JSON and Markdown output; `--fail-on` severity gate for CI.
- `mcp-detector.yml` configuration (rule groups, per-rule overrides, thresholds, ignore lists, active mode allow/deny).
- Passive-by-default scanning; opt-in `--active` mode that only calls tools that look read-only.
- Evasion-resistant text analysis: zero-width characters, full-width and homoglyph letters, and base64/hex-encoded payloads are normalised or decoded before pattern matching.
- MCP-031 network risk (capture/tunnel hosts, image-embedded exfiltration, internal and cloud-metadata addresses, non-HTTP schemes) and MCP-032 rug-pull detection.
- `mcp-detector pin` and `mcp-detector.lock.json` baseline; `scan --baseline` / `--no-baseline`.
- Labelled detection corpus (attack and benign samples) used as a regression suite for precision and recall.
- `scan-all`: batch scanning from a servers file, installed MCP clients' configs, or the official registry (remote servers only, passive, polite; package-based servers are never run).
- Scan history (`history`), score badges (`badge`, SVG and shields.io endpoint), script-free HTML report (`--format html`), static scoreboard site (`site`) and local read-only dashboard (`dashboard`).
- Community rules: declarative YAML/JSON rules (`--rules`, `community_rules:`) with ReDoS guards, and opt-in JavaScript plugins (`--allow-plugins`).
- Secrets in command lines and URLs are redacted before they are stored or published.
- Remote requests carry a `mcp-detector/<version>` User-Agent; authentication failures are classified as "needs authentication" rather than a broken server.
- `mcp-detector ui`: an interactive local web app (demo, paste a command, web address with sign-in headers, servers from installed MCP apps) with a hardened localhost-only security model (private access key in the URL fragment, Host/Origin checks, explicit consent to start programs, sandboxed script-free report frame, strict CSP).
- `mcp-detector demo` and a first-run menu when `mcp-detector` is run with no arguments in an interactive terminal.
- Plain-language explanations for connection failures (missing program, missing file, timeout, sign-in needed, unreachable address, wrong path) in the web app and in MCP-001 findings.
- No-code onboarding: a plain-language guide (`docs/for-beginners.md`) with screenshots, double-click launchers (`start-app.bat`, `start-app.command`) that check Node.js, set up on first run and open the web app, and an `npm run app` shortcut. The README now leads with this path.
- Community health: issue forms (bug, false positive, missed detection, rule proposal, feature), pull request template, label set and good-first-issue drafts with `scripts/setup-github.sh`.
- Animated terminal demo (`docs/images/demo.svg`, generated from real output by `npm run docs:demo`) at the top of the README, and hand-written release notes used by the release workflow.
- GitHub Action (`action.yml` at the repository root, so it can be listed on the GitHub Marketplace) with job-summary report.
- Example servers (`examples/secure-server`, `examples/vulnerable-server`) and a test suite with stdio and HTTP integration tests.
