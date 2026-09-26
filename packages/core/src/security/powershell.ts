import { spawn } from "node:child_process";

export class PowerShellError extends Error {
  constructor(
    message: string,
    /** machine-readable code the script printed to stderr, e.g. CERT_NOT_FOUND */
    readonly code: string,
  ) {
    super(message);
  }
}

/**
 * Runs a script in Windows PowerShell 5.1 (powershell.exe — present on every Windows 10/11,
 * and the only edition with WinRT access). Secrets go through stdin, never the command line.
 * A script reports failures as a single stderr line "CODE: message" and a non-zero exit.
 */
export function runPowerShell(script: string, stdin = ""): Promise<string> {
  // Without these, progress records land on stderr as CLIXML ("preparing modules for first
  // use") and messages come out in the OEM code page.
  const prelude = [
    "$ErrorActionPreference = 'Stop'",
    "$ProgressPreference = 'SilentlyContinue'",
    "[Console]::OutputEncoding = [Text.Encoding]::UTF8",
  ].join("\n");
  // Async WinRT failures arrive wrapped (MethodInvocation → Aggregate → the real one): unwrap.
  const wrapped =
    `${prelude}\ntry {\n${script}\n} catch {\n` +
    "$ex = $_.Exception; while ($ex.InnerException) { $ex = $ex.InnerException }\n" +
    '[Console]::Error.WriteLine("ERROR: " + $ex.Message + " (0x" + $ex.HResult.ToString("X8") + ")"); exit 1 }';
  return new Promise((resolve, reject) => {
    const child = spawn(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", Buffer.from(wrapped, "utf16le").toString("base64")],
      { windowsHide: true },
    );
    let out = "";
    let err = "";
    child.stdout.on("data", (d: Buffer) => (out += d.toString("utf8")));
    child.stderr.on("data", (d: Buffer) => (err += d.toString("utf8")));
    child.on("error", reject);
    child.on("close", (status) => {
      if (status === 0) return resolve(out.trim());
      reject(parseFailure(err, status));
    });
    child.stdin.end(stdin);
  });
}

/**
 * Picks our "CODE: message" line out of stderr; PowerShell may surround it with CLIXML
 * records ("#< CLIXML", "<Objs …>") and other noise.
 */
export function parseFailure(stderr: string, status: number | null): PowerShellError {
  const lines = stderr
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#< CLIXML") && !l.startsWith("<Objs"));
  const ours = [...lines].reverse().map((l) => /^([A-Z][A-Z0-9_]+): ?(.*)$/.exec(l)).find(Boolean);
  if (ours) return new PowerShellError(ours[2] || ours[1], ours[1]);
  return new PowerShellError(lines.at(-1) ?? `powershell exited with code ${status}`, "ERROR");
}
