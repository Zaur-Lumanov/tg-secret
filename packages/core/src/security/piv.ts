/**
 * PIV smart card commands (NIST SP 800-73-4) as implemented by YubiKey, over any
 * CardTransport. Only what unlocking needs: select, serial, PIN, RSA decryption.
 */
import { createHash } from "node:crypto";
import type { CardTransport } from "./pcsc.js";

const PIV_AID = Buffer.from("a000000308", "hex");
const ALG_RSA2048 = 0x07;

export class PivError extends Error {
  constructor(
    message: string,
    readonly sw: number,
  ) {
    super(message);
  }
}

export class WrongPinError extends PivError {
  constructor(readonly retriesLeft: number) {
    super(
      retriesLeft > 0
        ? `Wrong YubiKey PIN, tries left: ${retriesLeft}`
        : "The YubiKey PIN is blocked: unblock it with the PUK (ykman piv access unblock-pin)",
      0x63c0 | retriesLeft,
    );
  }
}

const sw = (resp: Buffer): number => resp.readUInt16BE(resp.length - 2);

function tlvLength(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  if (n < 0x100) return Buffer.from([0x81, n]);
  return Buffer.from([0x82, n >> 8, n & 0xff]);
}

const tlv = (tag: number, value: Buffer): Buffer => Buffer.concat([Buffer.from([tag]), tlvLength(value.length), value]);

/** Finds a tag in a flat TLV sequence and returns its value. */
function findTlv(data: Buffer, tag: number): Buffer | undefined {
  let off = 0;
  while (off < data.length) {
    const t = data[off++];
    let len = data[off++];
    if (len === 0x81) len = data[off++];
    else if (len === 0x82) {
      len = data.readUInt16BE(off);
      off += 2;
    }
    if (t === tag) return data.subarray(off, off + len);
    off += len;
  }
  return undefined;
}

export class Piv {
  constructor(private readonly card: CardTransport) {}

  /** Sends one APDU, collecting "61xx: more data available" continuations. */
  private async send(apdu: Buffer): Promise<{ data: Buffer; sw: number }> {
    let resp = await this.card.transmit(apdu);
    const chunks: Buffer[] = [];
    while ((sw(resp) & 0xff00) === 0x6100) {
      chunks.push(resp.subarray(0, -2));
      resp = await this.card.transmit(Buffer.from([0x00, 0xc0, 0x00, 0x00, sw(resp) & 0xff]));
    }
    chunks.push(resp.subarray(0, -2));
    return { data: Buffer.concat(chunks), sw: sw(resp) };
  }

  /** Long commands go out in 255-byte pieces (ISO 7816 command chaining, CLA 0x10). */
  private async sendChained(ins: number, p1: number, p2: number, data: Buffer): Promise<{ data: Buffer; sw: number }> {
    for (let off = 0; ; off += 255) {
      const chunk = data.subarray(off, off + 255);
      const last = off + 255 >= data.length;
      const apdu = Buffer.concat([
        Buffer.from([last ? 0x00 : 0x10, ins, p1, p2, chunk.length]),
        chunk,
        last ? Buffer.from([0x00]) : Buffer.alloc(0),
      ]);
      const res = await this.send(apdu);
      if (last) return res;
      if (res.sw !== 0x9000) return res;
    }
  }

  async select(): Promise<void> {
    const res = await this.send(Buffer.concat([Buffer.from([0x00, 0xa4, 0x04, 0x00, PIV_AID.length]), PIV_AID, Buffer.from([0x00])]));
    if (res.sw !== 0x9000) throw new PivError("The card has no PIV application", res.sw);
  }

  /** YubiKey-specific: the device serial number. */
  async serial(): Promise<number> {
    const res = await this.send(Buffer.from([0x00, 0xf8, 0x00, 0x00, 0x00]));
    if (res.sw !== 0x9000 || res.data.length < 4) throw new PivError("Failed to read the serial number", res.sw);
    return res.data.readUInt32BE(0);
  }

  async verifyPin(pin: string): Promise<void> {
    const bytes = Buffer.from(pin, "utf8");
    if (bytes.length < 6 || bytes.length > 8) throw new Error("The YubiKey PIN is 6 to 8 characters");
    const padded = Buffer.concat([bytes, Buffer.alloc(8 - bytes.length, 0xff)]);
    try {
      const res = await this.send(Buffer.concat([Buffer.from([0x00, 0x20, 0x00, 0x80, 0x08]), padded]));
      if (res.sw === 0x9000) return;
      if ((res.sw & 0xfff0) === 0x63c0) throw new WrongPinError(res.sw & 0x0f);
      if (res.sw === 0x6983) throw new WrongPinError(0);
      throw new PivError(`PIN verification error (0x${res.sw.toString(16)})`, res.sw);
    } finally {
      bytes.fill(0);
      padded.fill(0);
    }
  }

  /**
   * Raw RSA-2048 private key operation (GENERAL AUTHENTICATE) with the key in `slot`.
   * With touch policy "always" the card waits here until the key is touched.
   */
  async rsaRaw(slot: number, input: Buffer): Promise<Buffer> {
    if (input.length !== 256) throw new Error("RSA-2048: 256 bytes expected");
    const body = tlv(0x7c, Buffer.concat([Buffer.from([0x82, 0x00]), tlv(0x81, input)]));
    const res = await this.sendChained(0x87, ALG_RSA2048, slot, body);
    if (res.sw === 0x6982) throw new PivError("The YubiKey requires the PIN", res.sw);
    if (res.sw === 0x6a80 || res.sw === 0x6a82) throw new PivError("This YubiKey slot has no suitable key", res.sw);
    if (res.sw !== 0x9000) throw new PivError(`YubiKey error 0x${res.sw.toString(16)} (no touch?)`, res.sw);
    const outer = findTlv(res.data, 0x7c);
    const result = outer && findTlv(outer, 0x82);
    if (!result || result.length !== 256) throw new PivError("Unexpected YubiKey response", res.sw);
    return Buffer.from(result);
  }
}

function mgf1Sha1(seed: Buffer, length: number): Buffer {
  const out: Buffer[] = [];
  for (let counter = 0; out.length * 20 < length; counter++) {
    const c = Buffer.alloc(4);
    c.writeUInt32BE(counter);
    out.push(createHash("sha1").update(seed).update(c).digest());
  }
  return Buffer.concat(out).subarray(0, length);
}

/** RSAES-OAEP decoding (RFC 8017 §7.1.2) with SHA-1, MGF1-SHA-1 and an empty label. */
export function oaepDecodeSha1(em: Buffer): Buffer {
  const hLen = 20;
  const k = em.length;
  if (k < 2 * hLen + 2 || em[0] !== 0x00) throw new Error("OAEP: invalid format");
  const maskedSeed = em.subarray(1, 1 + hLen);
  const maskedDb = em.subarray(1 + hLen);
  const seedMask = mgf1Sha1(maskedDb, hLen);
  const seed = Buffer.from(maskedSeed.map((b, i) => b ^ seedMask[i]));
  const dbMask = mgf1Sha1(seed, k - hLen - 1);
  const db = Buffer.from(maskedDb.map((b, i) => b ^ dbMask[i]));
  const lHash = createHash("sha1").digest();
  if (!db.subarray(0, hLen).equals(lHash)) throw new Error("OAEP: invalid label hash");
  let i = hLen;
  while (i < db.length && db[i] === 0x00) i++;
  if (db[i] !== 0x01) throw new Error("OAEP: invalid padding");
  return Buffer.from(db.subarray(i + 1));
}
