/**
 * Minimal PC/SC binding (smart card access) through koffi FFI: winscard.dll on Windows,
 * PCSC.framework on macOS, libpcsclite on Linux. No admin rights are needed on any of them.
 */
import { createRequire } from "node:module";
import type { LibraryHandle } from "koffi";

type Koffi = typeof import("koffi");

/** koffi is an optional dependency: without it there is no PC/SC, so no YubiKey unlock in the console. */
function loadKoffi(): Koffi {
  try {
    return createRequire(import.meta.url)("koffi") as Koffi;
  } catch {
    throw new Error('Smart card support needs the optional "koffi" package, which is not installed');
  }
}

type Fn = ReturnType<LibraryHandle["func"]>;

const win = process.platform === "win32";
const mac = process.platform === "darwin";

// The same C API has different integer widths per platform.
const LONG = win || mac ? "int32_t" : "long";
const DWORD = win || mac ? "uint32_t" : "unsigned long";
const HANDLE = win ? "uintptr_t" : mac ? "int32_t" : "long";
const DWORD_SIZE = win || mac ? 4 : 8;

const SCARD_SCOPE_USER = 0;
const SCARD_SHARE_SHARED = 2;
const SCARD_PROTOCOL_T1 = 2;
const SCARD_LEAVE_CARD = 0;

const ERRORS: Record<number, string> = {
  0x8010001d: "the smart card service is not running (on Linux: install and start pcscd)",
  0x8010002e: "no smart card readers found (is the YubiKey plugged in?)",
  0x8010000c: "no card in the reader",
  0x80100069: "the key was removed",
  0x80100066: "the key is not responding",
  0x8010000b: "the key is in use by another program",
  0x80100017: "the reader is unavailable",
  0x80100006: "out of memory",
};

export class PcscError extends Error {
  constructor(
    readonly fn: string,
    readonly code: number,
  ) {
    super(`PC/SC ${fn}: ${ERRORS[code] ?? `error 0x${code.toString(16)}`}`);
  }
}

interface Api {
  establish: Fn;
  release: Fn;
  listReaders: Fn;
  connect: Fn;
  disconnect: Fn;
  begin: Fn;
  end: Fn;
  transmit: Fn;
}

let api: Api | undefined;

function load(): Api {
  if (api) return api;
  const koffi = loadKoffi();
  const lib = koffi.load(
    win ? "winscard.dll" : mac ? "/System/Library/Frameworks/PCSC.framework/PCSC" : "libpcsclite.so.1",
  );
  const A = win ? "A" : "";
  api = {
    establish: lib.func("SCardEstablishContext", LONG, [DWORD, "void *", "void *", koffi.out(koffi.pointer(HANDLE))]),
    release: lib.func("SCardReleaseContext", LONG, [HANDLE]),
    listReaders: lib.func(`SCardListReaders${A}`, LONG, [HANDLE, "void *", "uint8_t *", koffi.inout(koffi.pointer(DWORD))]),
    connect: lib.func(`SCardConnect${A}`, LONG, [
      HANDLE, "const char *", DWORD, DWORD, koffi.out(koffi.pointer(HANDLE)), koffi.out(koffi.pointer(DWORD)),
    ]),
    disconnect: lib.func("SCardDisconnect", LONG, [HANDLE, DWORD]),
    begin: lib.func("SCardBeginTransaction", LONG, [HANDLE]),
    end: lib.func("SCardEndTransaction", LONG, [HANDLE, DWORD]),
    transmit: lib.func("SCardTransmit", LONG, [
      HANDLE, "void *", "uint8_t *", DWORD, "void *", "uint8_t *", koffi.inout(koffi.pointer(DWORD)),
    ]),
  };
  return api;
}

/** PC/SC return codes come back signed on some platforms. */
const code = (rv: number | bigint): number => Number(BigInt.asUintN(32, BigInt(rv)));

function check(fn: string, rv: number | bigint): void {
  if (code(rv) !== 0) throw new PcscError(fn, code(rv));
}

/** A connection to one card, used by the PIV layer. */
export interface CardTransport {
  transmit(apdu: Buffer): Promise<Buffer>;
}

export class PcscContext {
  private readonly ctx: unknown;

  constructor() {
    const out = [0];
    check("EstablishContext", load().establish(SCARD_SCOPE_USER, null, null, out));
    this.ctx = out[0];
  }

  readers(): string[] {
    const len = [0];
    const rv = code(load().listReaders(this.ctx, null, null, len));
    if (rv === 0x8010002e) return [];
    check("ListReaders", rv);
    const buf = Buffer.alloc(Number(len[0]));
    check("ListReaders", load().listReaders(this.ctx, null, buf, len));
    return buf.toString("latin1").split("\0").filter(Boolean);
  }

  /** Runs `job` with exclusive access to the card (a PC/SC transaction). */
  async withCard<T>(reader: string, job: (card: CardTransport) => Promise<T>): Promise<T> {
    const a = load();
    const handle = [0];
    const protocol = [0];
    check("Connect", a.connect(this.ctx, reader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, handle, protocol));
    const card = handle[0];
    // SCARD_IO_REQUEST { dwProtocol; cbPciLength }
    const pci = Buffer.alloc(DWORD_SIZE * 2);
    if (DWORD_SIZE === 4) {
      pci.writeUInt32LE(Number(protocol[0]), 0);
      pci.writeUInt32LE(8, 4);
    } else {
      pci.writeBigUInt64LE(BigInt(protocol[0]), 0);
      pci.writeBigUInt64LE(16n, 8);
    }
    try {
      check("BeginTransaction", a.begin(card));
      try {
        return await job({
          transmit: (apdu) =>
            new Promise<Buffer>((resolve, reject) => {
              const recv = Buffer.alloc(4096);
              const recvLen = [recv.length];
              // async: a touch-to-confirm operation blocks until the key is touched
              a.transmit.async(card, pci, apdu, apdu.length, null, recv, recvLen, (err: unknown, rv: number) => {
                if (err) return reject(err);
                if (code(rv) !== 0) return reject(new PcscError("Transmit", code(rv)));
                resolve(Buffer.from(recv.subarray(0, Number(recvLen[0]))));
              });
            }),
        });
      } finally {
        a.end(card, SCARD_LEAVE_CARD);
      }
    } finally {
      a.disconnect(card, SCARD_LEAVE_CARD);
    }
  }

  close(): void {
    load().release(this.ctx);
  }
}
