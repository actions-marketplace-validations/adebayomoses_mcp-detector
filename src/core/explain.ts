export interface ErrorExplanation {
  /** One short sentence saying what went wrong, in plain language. */
  title: string;
  /** What the person can do about it. */
  hint: string;
}

export interface ErrorContext {
  command?: string;
  url?: string;
  timeoutMs?: number;
  /** Last lines the server wrote to stderr, if any. */
  stderr?: string;
}

/** The first word of a command line, without folders or a Windows ".exe" ending ("C:\\Python\\python.exe -m x" -> "python"). */
function programName(command: string): string {
  const first = command.trim().split(/\s+/)[0] ?? "";
  return (first.split(/[\\/]/).pop() ?? first).replace(/\.exe$/i, "");
}

const PYTHON_TOOLS = /^(?:uvx?|pipx?|pip3|python(?:\d+(?:\.\d+)?)?|py)$/i;

/** Where to get the Python tools, for the "program not found" case. Undefined for anything else. */
function pythonInstallHint(program: string): string | undefined {
  const name = program.toLowerCase();
  if (!PYTHON_TOOLS.test(name)) return undefined;
  if (name === "uv" || name === "uvx")
    return `"${program}" comes with uv. Install uv from https://docs.astral.sh/uv/getting-started/installation/, then open a new terminal and try again.`;
  if (name === "pipx")
    return 'Install pipx (https://pipx.pypa.io/stable/installation/), then open a new terminal and try again. Or switch the command to "uvx", which needs only uv.';
  if (/^pip/.test(name))
    return 'pip comes with Python. Install Python from https://www.python.org/downloads/ (on Windows, tick "Add python.exe to PATH"), then open a new terminal and try again.';
  return `Install Python from https://www.python.org/downloads/ (on Windows, tick "Add python.exe to PATH"), then open a new terminal and try again. On some computers the command is "python3" or "py" instead of "${program}".`;
}

/**
 * Turn a low-level connection error into something a first-time user can act on.
 * The raw error is always kept elsewhere (reports show it as evidence); this only adds guidance.
 */
export function explainConnectError(raw: string, ctx: ErrorContext = {}): ErrorExplanation {
  const err = raw ?? "";
  const stderr = ctx.stderr ?? "";
  const seconds = Math.round((ctx.timeoutMs ?? 30000) / 1000);

  if (/\b(401|403)\b|unauthori[sz]ed|forbidden|not authenticated|authentication (?:is )?required|\b(?:invalid|missing|expired|bad)\b[^.]{0,25}\b(?:token|api[ _-]?key|credentials?|authorization)\b|oauth/i.test(err))
    return {
      title: "This server needs you to sign in.",
      hint: 'It rejected the connection because no valid credentials were sent. If you have a token, add it as a header, for example --header "Authorization: Bearer YOUR_TOKEN" (or the Headers box in the web app).',
    };

  if (/Invalid URL/i.test(err))
    return { title: "That does not look like a valid web address.", hint: "Use the full address, starting with https:// (or http:// for a server on your own computer)." };

  // The server printed something other than MCP messages on stdout before or during the handshake.
  // Usually a stray print() or a logger writing to stdout. Checked early: the parse error can look like a crash.
  if (!ctx.url && /Unexpected token|Unexpected non-whitespace|(?:is not|invalid|malformed) (?:valid )?JSON|JSON\.parse|Unexpected end of JSON/i.test(err))
    return {
      title: "The server printed something that is not an MCP message.",
      hint: "MCP servers that run on your computer talk over stdout, so nothing else may be printed there. Look for print() calls (Python) or console.log (Node) and send them to stderr instead, for example print(..., file=sys.stderr) or logging.basicConfig(stream=sys.stderr).",
    };

  // The program exists but is too old for the server (uv/pip/Python messages). Checked before the missing-package case:
  // an installer can say both.
  const old = `${err}\n${stderr}`;
  if (/requires-python|requires a different Python|Python\s+\d+(?:\.\d+)*\s+is not supported|requires Python\s*(?:[<>=!~]|\d)|python_requires|only supports Python/i.test(old)) {
    const at = old.search(/requires-python|requires a different Python|requires Python|python_requires|only supports Python|is not supported/i);
    const needed = at < 0 ? undefined : /(?:>=|>|~=)\s*(\d+\.\d+)/.exec(old.slice(at))?.[1];
    return {
      title: "The server needs a newer version of Python.",
      hint: `${needed ? `It needs Python ${needed} or newer. ` : ""}Install a newer Python from https://www.python.org/downloads/, or let uv pick one for you (for example: uvx --python 3.12 your-server). Then try again.`,
    };
  }

  // The program exists but a file or package it needs does not: checked before "not found", because its stderr can also say that.
  const missingPy = /No module named ['"]?([\w.-]+)/i.exec(stderr) ?? /ModuleNotFoundError[^\n]*?['"]([\w.-]+)['"]/i.exec(stderr);
  if (missingPy || /ModuleNotFoundError|No module named/i.test(stderr)) {
    const top = missingPy?.[1]?.split(".")[0];
    return {
      title: top ? `The Python server needs a package called "${top}" that is not installed.` : "The Python server needs a package that is not installed.",
      hint: `Install it in the same Python the server runs with (for example: pip install ${top ?? "the-package"}), or start the server with uvx or uv run so its packages are installed for you. The name you install by can differ slightly from the name in the error.`,
    };
  }

  if (/MODULE_NOT_FOUND|Cannot find module/i.test(stderr))
    return {
      title: "The server crashed on start because a file or package is missing.",
      hint: "Run the same command in a terminal to see the full error. You probably need to install its dependencies first (npm install) or fix the path to the script.",
    };

  // The program itself does not exist. Depending on the OS and shell this shows up in the error or only on stderr
  // (Windows: "'x' is not recognized as an internal or external command"; sh: "x: not found").
  if (ctx.command && /ENOENT|is not recognized as an internal|command not found|: not found\b|not found in PATH|Python was not found/i.test(`${err}\n${stderr}`)) {
    const program = programName(ctx.command);
    return {
      title: `The program "${program}" was not found.`,
      hint:
        pythonInstallHint(program) ??
        "Check the spelling, and make sure it is installed and on your PATH. For Node servers start the command with node or npx; for Python servers use python or uvx.",
    };
  }

  if (/ECONNREFUSED|ENOTFOUND|EAI_AGAIN|fetch failed|ECONNRESET|certificate|ETIMEDOUT/i.test(err))
    return {
      title: `Could not reach ${ctx.url ? new URL(ctx.url).host : "the server"}.`,
      hint: "Check the address, your internet connection, and that the server is actually running. For a server on your own computer, start it first.",
    };

  if (/timed out/i.test(err))
    return {
      title: `The server did not finish starting within ${seconds} seconds.`,
      hint: ctx.command && /^(npx|uvx|pnpm|bunx|dlx)/i.test(ctx.command)
        ? "The first run of npx or uvx has to download the package, which can be slow. Try again; the second run is usually much faster. You can also raise the limit with --timeout."
        : "It may be hanging or waiting for input. Run the command in a terminal to see what it prints, or raise the limit with --timeout.",
    };

  if (/protocol version/i.test(err))
    return {
      title: "The server speaks a protocol version this tool does not know.",
      hint: "Update the server's MCP SDK to a current release, or update mcp-detector if the server is newer.",
    };

  if (/\b404\b/.test(err) && ctx.url)
    return { title: "The address answered, but there is no MCP server at that path.", hint: "MCP endpoints are often at a path such as /mcp or /sse. Check the server's documentation for the right URL." };

  if (/Connection closed|exited|EPIPE/i.test(err))
    return {
      title: "The server stopped right after starting.",
      hint: stderr.trim()
        ? "Its own error output is shown below the finding. Fix that, then try again."
        : "Run the same command in a terminal to see why it exits; servers often print the reason when they stop.",
    };

  return { title: "Could not connect to the server.", hint: "Run the same command (or open the same address) on its own to check that it works, then try again." };
}
