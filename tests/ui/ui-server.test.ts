import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startUiServer, type UiServer } from "../../src/ui/server.js";
import { explainConnectError } from "../../src/core/explain.js";
import { example } from "../fixtures/run-cli.js";

interface Res { status: number; headers: Record<string, string | string[] | undefined>; text: string; json: any }

function call(port: number, o: { method?: string; path?: string; headers?: Record<string, string>; body?: string | object } = {}): Promise<Res> {
  return new Promise((resolve, reject) => {
    const body = o.body === undefined ? undefined : typeof o.body === "string" ? o.body : JSON.stringify(o.body);
    const req = httpRequest(
      {
        host: "127.0.0.1",
        port,
        method: o.method ?? "GET",
        path: o.path ?? "/",
        headers: { host: `127.0.0.1:${port}`, ...(body !== undefined ? { "content-length": String(Buffer.byteLength(body)) } : {}), ...(o.headers ?? {}) },
      },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () => {
          let j: any;
          try { j = JSON.parse(text); } catch { /* not json */ }
          resolve({ status: res.statusCode ?? 0, headers: res.headers, text, json: j });
        });
      },
    );
    req.on("error", reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

const node = process.execPath;
let ui: UiServer;
let cwd: string;
const auth = () => ({ "x-mcpd-token": ui.token });
const jsonHeaders = () => ({ ...auth(), "content-type": "application/json" });
const post = (body: unknown, headers: Record<string, string> = jsonHeaders()) => call(ui.port, { method: "POST", path: "/api/scan", headers, body: body as object });

async function finish(id: string, timeoutMs = 45_000) {
  const start = Date.now();
  for (;;) {
    const r = await call(ui.port, { path: `/api/scan/${id}`, headers: auth() });
    if (r.json.status !== "running") return r.json;
    if (Date.now() - start > timeoutMs) throw new Error("scan did not finish");
    await new Promise((ok) => setTimeout(ok, 150));
  }
}

beforeAll(async () => {
  cwd = mkdtempSync(join(tmpdir(), "mcpd-ui-"));
  ui = await startUiServer({
    port: 0,
    cwd,
    open: false,
    discover: () => ({
      files: [],
      errors: [],
      specs: [
        { name: "secure-via-client", source: "Test App", server: { command: node, args: [example("secure-server")], env: { API_SECRET: "env-secret-value-777" } } },
        { name: "remote", source: "Test App", server: { url: "https://example.com/mcp", headers: { Authorization: "Bearer header-secret-value-888" } } },
      ],
    }),
  });
});
afterAll(() => ui.close());

describe("the page", () => {
  it("is served with a strict CSP, no remote resources and no access key inside", async () => {
    const r = await call(ui.port);
    expect(r.status).toBe(200);
    const csp = String(r.headers["content-security-policy"]);
    const nonce = /script-src 'nonce-([^']+)'/.exec(csp)![1];
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("connect-src 'self'");
    expect(r.text).toContain(`<script nonce="${nonce}">`);
    expect(r.text.match(/<script/g)).toHaveLength(1);
    expect(r.text).not.toContain(ui.token);
    expect(r.text).not.toMatch(/(src|href|action)=["']https?:/i); // nothing is loaded from the network
    expect(r.headers["x-frame-options"]).toBe("DENY");
    expect(r.headers["x-content-type-options"]).toBe("nosniff");
    expect(r.headers["cache-control"]).toBe("no-store");
    expect(r.text).toContain("Try the demo");
    expect(r.text).toContain('sandbox=""'); // reports are shown in a fully sandboxed frame
  });
  it("uses a fresh nonce for every response", async () => {
    const a = String((await call(ui.port)).headers["content-security-policy"]);
    const b = String((await call(ui.port)).headers["content-security-policy"]);
    expect(a).not.toBe(b);
  });
  it("the access link keeps the key in the fragment, which browsers never send to a server", () => {
    expect(ui.url).toMatch(new RegExp(`^http://127\\.0\\.0\\.1:${ui.port}/#token=[a-f0-9]{48}$`));
  });
});

describe("who may talk to it", () => {
  it("answers only requests addressed to localhost on its own port (DNS-rebinding defence)", async () => {
    for (const host of ["evil.example", `evil.example:${ui.port}`, "127.0.0.1:1", "localhost"]) {
      const page = await call(ui.port, { headers: { host } });
      const api = await call(ui.port, { path: "/api/state", headers: { ...auth(), host } });
      expect([page.status, api.status], host).toEqual([403, 403]);
    }
    expect((await call(ui.port, { headers: { host: `localhost:${ui.port}` } })).status).toBe(200);
  });
  it("requires the access key for every API call", async () => {
    const attempts: Record<string, string>[] = [{}, { "x-mcpd-token": "wrong" }, { "x-mcpd-token": ui.token.slice(0, -1) }, { "x-mcpd-token": ui.token + "0" }, { "x-mcpd-token": "" }];
    for (const headers of attempts) {
      expect((await call(ui.port, { path: "/api/state", headers })).status).toBe(401);
    }
    expect((await call(ui.port, { path: "/api/state", headers: auth() })).status).toBe(200);
  });
  it("refuses cross-site requests even with the right key", async () => {
    expect((await call(ui.port, { path: "/api/state", headers: { ...auth(), origin: "https://evil.example" } })).status).toBe(403);
    expect((await call(ui.port, { path: "/api/state", headers: { ...auth(), "sec-fetch-site": "cross-site" } })).status).toBe(403);
    expect((await call(ui.port, { path: "/api/state", headers: { ...auth(), "sec-fetch-site": "same-site" } })).status).toBe(403);
    expect((await call(ui.port, { path: "/api/state", headers: { ...auth(), origin: `http://127.0.0.1:${ui.port}`, "sec-fetch-site": "same-origin" } })).status).toBe(200);
  });
  it("sends no CORS headers and rejects other methods", async () => {
    const pre = await call(ui.port, { method: "OPTIONS", path: "/api/scan", headers: { origin: "https://evil.example", "access-control-request-method": "POST" } });
    expect(pre.status).toBe(405);
    expect(pre.headers["access-control-allow-origin"]).toBeUndefined();
    expect((await call(ui.port, { path: "/api/state", headers: auth() })).headers["access-control-allow-origin"]).toBeUndefined();
    for (const method of ["PUT", "DELETE", "PATCH"]) expect((await call(ui.port, { method, path: "/api/scan", headers: auth() })).status).toBe(405);
  });
  it("only listens on the loopback interface", () => {
    const addr = (ui as any).address;
    expect(addr).toBeUndefined(); // no public handle exposed
    expect(ui.url.startsWith("http://127.0.0.1:")).toBe(true);
  });
});

describe("what the state endpoint reveals", () => {
  it("lists installed servers by name and redacted command, never their environment or headers", async () => {
    const r = await call(ui.port, { path: "/api/state", headers: auth() });
    expect(r.json.clients.map((c: any) => c.name)).toEqual(["secure-via-client", "remote"]);
    expect(r.text).not.toContain("env-secret-value-777");
    expect(r.text).not.toContain("header-secret-value-888");
    expect(r.json.version).toMatch(/^\d+\.\d+\.\d+/);
  });
});

describe("input validation", () => {
  it("rejects bad requests with clear messages", async () => {
    expect((await post({ kind: "demo", name: "vulnerable" }, auth())).status).toBe(415); // not declared as JSON
    expect((await post("{not json")).status).toBe(400);
    expect((await post({ kind: "nope" })).status).toBe(400);
    expect((await post({ kind: "demo", name: "../../etc/passwd" })).status).toBe(400);
    const big = await post({ kind: "command", command: "x".repeat(70_000), confirm: true });
    expect(big.status).toBe(413);
  });
  it("will not start a program without explicit confirmation", async () => {
    const r = await post({ kind: "command", command: `${node} -v` });
    expect(r.status).toBe(400);
    expect(r.json.error).toMatch(/tick the box/i);
    expect((await post({ kind: "command", command: `${node} -v`, confirm: "yes" })).status).toBe(400); // must be literally true
    expect((await post({ kind: "client", id: 0 })).status).toBe(400);
  });
  it("validates commands, URLs and headers", async () => {
    expect((await post({ kind: "command", command: "  ", confirm: true })).status).toBe(400);
    expect((await post({ kind: "command", command: "a\nb", confirm: true })).status).toBe(400);
    expect((await post({ kind: "url", url: "not a url" })).status).toBe(400);
    expect((await post({ kind: "url", url: "file:///etc/passwd" })).status).toBe(400);
    expect((await post({ kind: "url", url: "ftp://example.com" })).status).toBe(400);
    expect((await post({ kind: "url", url: "https://example.com", headers: { "Bad Name": "x" } })).status).toBe(400);
    expect((await post({ kind: "url", url: "https://example.com", headers: { Authorization: "a\r\nX-Injected: 1" } })).status).toBe(400);
    expect((await post({ kind: "url", url: "https://example.com", headers: Object.fromEntries(Array.from({ length: 11 }, (_, i) => [`H${i}`, "v"])) })).status).toBe(400);
    for (const id of [-1, 99, 1.5, "0", null]) expect((await post({ kind: "client", id, confirm: true })).status, String(id)).toBe(400);
  });
  it("unknown routes and malformed ids are 404; history keys cannot traverse paths", async () => {
    for (const p of ["/api/nope", "/api/scan/xyz", "/api/scan/0123456789abcdef", "/api/history/../../package.json", "/api/history/ZZZ", "/nope"]) {
      expect((await call(ui.port, { path: p, headers: auth() })).status, p).toBe(404);
    }
  });
});

describe("scanning through the app", () => {
  it("demo: runs, returns a score, and a report that contains no scripts", async () => {
    const r = await post({ kind: "demo", name: "vulnerable" });
    expect(r.status).toBe(202);
    const job = await finish(r.json.id);
    expect(job.status).toBe("done");
    expect(job.result.score).toBeLessThan(70);
    expect(job.result.status).toBe("connected");
    expect(job.html.startsWith("<!doctype html>")).toBe(true);
    expect(job.html).not.toMatch(/<script/i);
    expect(job.html).toContain("MCP-012");
  }, 60_000);

  it("a typed command, once confirmed, scans a real server", async () => {
    const line = `"${node}" "${example("secure-server")}"`;
    const r = await post({ kind: "command", command: line, confirm: true });
    expect(r.status).toBe(202);
    const job = await finish(r.json.id);
    expect(job.result.score).toBe(100);
    expect(job.result.timings.avgToolMs).toBeUndefined(); // passive unless asked
  }, 60_000);

  it("'active' is opt-in per scan", async () => {
    const line = `"${node}" "${example("secure-server")}"`;
    const job = await finish((await post({ kind: "command", command: line, confirm: true, active: true })).json.id);
    expect(job.result.timings.avgToolMs).toBeDefined();
  }, 60_000);

  it("a server picked from the installed list is run by id (the browser never supplies its command)", async () => {
    const r = await post({ kind: "client", id: 0, confirm: true });
    expect(r.status).toBe(202);
    const job = await finish(r.json.id);
    expect(job.label).toBe("secure-via-client");
    expect(job.result.score).toBe(100);
    expect(JSON.stringify(job)).not.toContain("env-secret-value-777");
  }, 60_000);

  it("a server that cannot start is explained in plain language, not just a raw error", async () => {
    const line = `"${node}" "${join(cwd, "does-not-exist.mjs")}"`;
    const job = await finish((await post({ kind: "command", command: line, confirm: true })).json.id);
    expect(job.status).toBe("done");
    expect(job.result.status).toBe("failed");
    expect(job.problem.title.length).toBeGreaterThan(10);
    expect(job.problem.hint.length).toBeGreaterThan(20);
    expect(job.html).toContain("MCP-001");
  }, 60_000);

  it("scans are recorded in history and can be reopened", async () => {
    const list = await call(ui.port, { path: "/api/history", headers: auth() });
    expect(list.json.items.length).toBeGreaterThan(0);
    const one = await call(ui.port, { path: `/api/history/${list.json.items[0].key}`, headers: auth() });
    expect(one.status).toBe(200);
    expect(one.json.html.startsWith("<!doctype html>")).toBe(true);
  });
});

describe("credentials typed into the app", () => {
  let remote: Server;
  let seenAuth: string[] = [];
  beforeAll(async () => {
    remote = createServer((req, res) => {
      seenAuth.push(String(req.headers.authorization));
      res.writeHead(401, { "content-type": "application/json" }).end('{"error":"unauthorized"}');
    });
    await new Promise<void>((ok) => remote.listen(0, "127.0.0.1", ok));
  });
  afterAll(() => new Promise<void>((ok) => remote.close(() => ok())));

  it("are sent to the server being scanned, and appear nowhere in what the app returns or stores", async () => {
    const secret = "Bearer typed-secret-value-999";
    const url = `http://127.0.0.1:${(remote.address() as AddressInfo).port}/mcp?access_token=query-secret-555`;
    const r = await post({ kind: "url", url, headers: { Authorization: secret } });
    expect(r.status).toBe(202);
    const job = await finish(r.json.id);
    expect(seenAuth.some((a) => a === secret)).toBe(true); // it really was used
    const all = JSON.stringify(job) + r.text;
    expect(all).not.toContain("typed-secret-value-999");
    expect(all).not.toContain("query-secret-555");
    expect(job.problem.title).toMatch(/sign in/i); // and the failure is explained helpfully
    const list = await call(ui.port, { path: "/api/scan/" + r.json.id, headers: auth() });
    expect(list.text).not.toContain("typed-secret-value-999");
  }, 60_000);
});

describe("limits", () => {
  it("allows only a couple of scans at once, and tells the person to wait", async () => {
    const hang = await startUiServer({ port: 0, cwd, open: false, maxRunning: 2, runner: () => new Promise(() => {}) });
    try {
      const h = { "x-mcpd-token": hang.token, "content-type": "application/json" };
      const start = () => call(hang.port, { method: "POST", path: "/api/scan", headers: h, body: { kind: "demo", name: "secure" } });
      expect((await start()).status).toBe(202);
      expect((await start()).status).toBe(202);
      const third = await start();
      expect(third.status).toBe(429);
      expect(third.json.error).toMatch(/wait/i);
    } finally {
      await hang.close();
    }
  });
  it("stops listening when closed", async () => {
    const tmp = await startUiServer({ port: 0, open: false, discover: () => ({ specs: [], files: [], errors: [] }) });
    const port = tmp.port;
    await tmp.close();
    await expect(call(port)).rejects.toThrow();
  });
});

describe("plain-language error explanations", () => {
  const e = (raw: string, ctx: object = {}) => explainConnectError(raw, ctx);
  it.each([
    ["spawn nope ENOENT", { command: "nope" }, /was not found/],
    ["Connection closed", { command: "nope --serve", stderr: "'nope' is not recognized as an internal or external command," }, /"nope" was not found/],
    ["Connection closed", { command: "nope", stderr: "sh: 1: nope: not found" }, /was not found/],
    ["Connection closed", { command: "node missing.js", stderr: "Error: Cannot find module '/x/missing.js'\n  code: 'MODULE_NOT_FOUND'" }, /file or package is missing/],
    ["Connection closed", { stderr: "Error: Cannot find module '/x/y.js'" }, /file or package is missing/],
    ["Connection closed", {}, /stopped right after starting/],
    ["Connection timed out after 30000 ms", { command: "npx -y something", timeoutMs: 30000 }, /download the package/],
    ["Connection timed out after 5000 ms", { command: "node s.js", timeoutMs: 5000 }, /hanging or waiting/],
    ["fetch failed ECONNREFUSED", { url: "http://localhost:9/mcp" }, /Could not reach localhost:9/],
    ["Error POSTing to endpoint: 401 Unauthorized", { url: "https://x.example" }, /sign in/],
    ["Invalid URL", {}, /valid web address/],
    ["Server's protocol version is not supported: 1999-01-01", {}, /protocol version/],
    ["Error POSTing to endpoint: 404 Not Found", { url: "https://x.example/wrong" }, /no MCP server at that path/],
    // Python servers (uvx, uv run, python -m, pipx)
    ["spawn uvx ENOENT", { command: "uvx my-server" }, /"uvx" was not found[\s\S]*docs\.astral\.sh\/uv/],
    ["spawn uv ENOENT", { command: "uv run server.py" }, /"uv" was not found[\s\S]*docs\.astral\.sh\/uv/],
    ["spawn python ENOENT", { command: "python -m my_server" }, /"python" was not found[\s\S]*python\.org\/downloads[\s\S]*python3/],
    ["Connection closed", { command: "python3 server.py", stderr: "bash: python3: command not found" }, /"python3" was not found[\s\S]*python\.org/],
    ["Connection closed", { command: "python server.py", stderr: "Python was not found; run without arguments to install from the Microsoft Store" }, /"python" was not found[\s\S]*python\.org/],
    ["spawn pipx ENOENT", { command: "pipx run my-server" }, /"pipx" was not found[\s\S]*pipx\.pypa\.io/],
    ["spawn C:\\Python312\\python.exe ENOENT", { command: "C:\\Python312\\python.exe -m s" }, /"python" was not found/],
    ["Connection closed", { command: "python -m my_server", stderr: "Traceback (most recent call last):\n  File <frozen runpy>, line 198\nModuleNotFoundError: No module named 'httpx'" }, /package called "httpx"[\s\S]*pip install httpx/],
    ["Connection closed", { command: "python server.py", stderr: "ModuleNotFoundError: No module named 'mcp.server.fastmcp'" }, /package called "mcp"[\s\S]*pip install mcp/],
    ["Connection closed", { stderr: "/usr/bin/python: No module named my_server" }, /package called "my_server"/],
    ["Connection closed", { command: "uvx my-server", stderr: "error: The current Python version (3.8.10) is not compatible with the package's requires-python>=3.10" }, /newer version of Python[\s\S]*Python 3\.10 or newer/],
    ["Connection closed", { command: "pipx run my-server", stderr: "ERROR: Package 'my-server' requires a different Python: 3.8.10 not in '>=3.11'" }, /newer version of Python[\s\S]*Python 3\.11 or newer/],
    ["Connection closed", { command: "python server.py", stderr: "RuntimeError: Python 3.7 is not supported by this package" }, /newer version of Python/],
    // Version problem wins over a missing-package message that an installer may print as well.
    ["Connection closed", { stderr: "requires-python>=3.12\nModuleNotFoundError: No module named 'x'" }, /newer version of Python[\s\S]*3\.12/],
    // A stray print() corrupts the stream: the client reports JSON parse errors.
    [`Unexpected token 'S', "Starting my server..." is not valid JSON`, { command: "python server.py" }, /not an MCP message[\s\S]*stderr/],
    ["Unexpected non-whitespace character after JSON at position 4", { command: "uv run server.py" }, /not an MCP message/],
    ["SyntaxError: invalid JSON from server", { command: "python server.py" }, /not an MCP message/],
  ])("%s", (raw, ctx, title) => {
    const out = e(raw, ctx);
    expect(out.title + " " + out.hint).toMatch(title);
    expect(out.hint.length).toBeGreaterThan(20);
  });
  it("does not blame stdout printing when a web address returned a non-JSON page", () => {
    const out = e(`Unexpected token '<', "<!DOCTYPE "... is not valid JSON`, { url: "https://x.example/mcp" });
    expect(out.title).not.toMatch(/not an MCP message/);
  });
  it("keeps the Node hints for Node servers", () => {
    const out = e("spawn nope ENOENT", { command: "nope" });
    expect(out.hint).toMatch(/node or npx/);
    expect(out.hint).not.toMatch(/python\.org/);
  });
  it("keeps hints short and free of raw error text", () => {
    const out = e("Connection closed", { command: "python s.py", stderr: "ModuleNotFoundError: No module named 'httpx'" });
    expect(out.hint.length).toBeLessThan(400);
  });
  it("always gives a usable fallback", () => {
    expect(e("something unexpected").title).toBe("Could not connect to the server.");
  });
});
