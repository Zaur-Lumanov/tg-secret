// Builds the Touch ID helper (native/touchid.swift → native/tg-secret-touchid), a universal
// arm64 + x86_64 binary with an ad-hoc signature. macOS only, needs the Xcode Command Line
// Tools (xcode-select --install). Elsewhere it does nothing; on a Mac without swiftc it warns,
// unless --required is passed (for release builds, where the package must include it).
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const required = process.argv.includes("--required");
const native = fileURLToPath(new URL("../native/", import.meta.url));
const source = join(native, "touchid.swift");
const output = join(native, "tg-secret-touchid");

if (process.platform !== "darwin") {
  if (required) throw new Error("the Touch ID helper can only be built on macOS");
  process.exit(0);
}

const run = (cmd, args) => execFileSync(cmd, args, { stdio: "inherit" });

try {
  execFileSync("xcrun", ["--find", "swiftc"], { stdio: "ignore" });
} catch {
  if (required) throw new Error("swiftc not found: install the Xcode Command Line Tools (xcode-select --install)");
  console.warn("warning: swiftc not found, the Touch ID helper was not built (xcode-select --install)");
  process.exit(0);
}

const tmp = mkdtempSync(join(tmpdir(), "tg-secret-touchid-"));
try {
  const slices = ["arm64", "x86_64"].map((arch) => {
    const out = join(tmp, arch);
    run("xcrun", ["swiftc", "-O", "-target", `${arch}-apple-macos11`, source, "-o", out]);
    return out;
  });
  run("lipo", ["-create", ...slices, "-output", output]);
  run("codesign", ["--force", "--sign", "-", output]);
  console.log(`built ${output}`);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
