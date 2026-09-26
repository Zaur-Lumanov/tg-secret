import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { uniquePath } from "../media/files.js";
import { atomicWrite, secureDelete } from "./vault.js";

const PREFIX = "tg-secret-";

/** True if a process with this pid exists (EPERM: it does, but belongs to another user). */
export const processAlive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
};

/**
 * Decrypted copies of files, made only so an external viewer can open them.
 * They live in a per-process temp directory and are wiped on /lock and on exit.
 */
export class TempFiles {
  private dir?: string;

  constructor() {
    process.once("exit", () => this.wipe());
  }

  /** Removes directories left by previous runs that crashed or were killed. */
  static sweepStale(): void {
    for (const name of readdirSync(tmpdir())) {
      const pid = Number(/^tg-secret(?:-cli)?-(\d+)-/.exec(name)?.[1]);
      if (!pid || pid === process.pid || processAlive(pid)) continue;
      wipeDir(join(tmpdir(), name));
    }
  }

  write(name: string, data: Buffer): string {
    if (!this.dir) {
      this.dir = join(tmpdir(), `${PREFIX}${process.pid}-${randomBytes(6).toString("hex")}`);
      mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    }
    const path = uniquePath(this.dir, name);
    atomicWrite(path, data);
    return path;
  }

  /** Best effort: a file still open in a viewer on Windows can't be deleted now; sweepStale gets it later. */
  wipe(): void {
    if (this.dir) wipeDir(this.dir);
    this.dir = undefined;
  }
}

function wipeDir(dir: string): void {
  if (!existsSync(dir)) return;
  for (const name of readdirSync(dir)) {
    try {
      secureDelete(join(dir, name));
    } catch {
      // locked by another process
    }
  }
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    // not empty: some file is still locked
  }
}
