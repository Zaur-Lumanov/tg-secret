/**
 * Minimal TL binary (de)serialization primitives.
 * https://core.telegram.org/mtproto/serialize
 */

export const VECTOR_ID = 0x1cb5c415;

export class TLWriter {
  private chunks: Buffer[] = [];

  int(value: number): this {
    const b = Buffer.alloc(4);
    b.writeInt32LE(value | 0);
    this.chunks.push(b);
    return this;
  }

  /** Writes a constructor id (unsigned 32-bit). */
  id(value: number): this {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(value >>> 0);
    this.chunks.push(b);
    return this;
  }

  long(value: bigint): this {
    const b = Buffer.alloc(8);
    b.writeBigInt64LE(BigInt.asIntN(64, value));
    this.chunks.push(b);
    return this;
  }

  bytes(data: Buffer): this {
    let header: Buffer;
    if (data.length < 254) {
      header = Buffer.from([data.length]);
    } else {
      header = Buffer.alloc(4);
      header[0] = 254;
      header.writeUIntLE(data.length, 1, 3);
    }
    const total = header.length + data.length;
    const padding = (4 - (total % 4)) % 4;
    this.chunks.push(header, data, Buffer.alloc(padding));
    return this;
  }

  string(value: string): this {
    return this.bytes(Buffer.from(value, "utf8"));
  }

  raw(data: Buffer): this {
    this.chunks.push(data);
    return this;
  }

  longVector(values: bigint[]): this {
    return this.vector(values, (v) => this.long(v));
  }

  vector<T>(values: T[], item: (v: T) => void): this {
    this.id(VECTOR_ID).int(values.length);
    for (const v of values) item(v);
    return this;
  }

  toBuffer(): Buffer {
    return Buffer.concat(this.chunks);
  }
}

export class TLReader {
  private offset = 0;

  constructor(private readonly buf: Buffer) {}

  get remaining(): number {
    return this.buf.length - this.offset;
  }

  private ensure(n: number): void {
    if (this.offset + n > this.buf.length) {
      throw new Error(`TLReader: unexpected end of data (need ${n}, have ${this.remaining})`);
    }
  }

  int(): number {
    this.ensure(4);
    const v = this.buf.readInt32LE(this.offset);
    this.offset += 4;
    return v;
  }

  id(): number {
    this.ensure(4);
    const v = this.buf.readUInt32LE(this.offset);
    this.offset += 4;
    return v;
  }

  long(): bigint {
    this.ensure(8);
    const v = this.buf.readBigInt64LE(this.offset);
    this.offset += 8;
    return v;
  }

  double(): number {
    this.ensure(8);
    const v = this.buf.readDoubleLE(this.offset);
    this.offset += 8;
    return v;
  }

  bytes(): Buffer {
    this.ensure(1);
    let len = this.buf[this.offset];
    let headerLen = 1;
    if (len === 254) {
      this.ensure(4);
      len = this.buf.readUIntLE(this.offset + 1, 3);
      headerLen = 4;
    } else if (len === 255) {
      throw new Error("TLReader: invalid bytes length prefix 255");
    }
    this.ensure(headerLen + len);
    const data = Buffer.from(this.buf.subarray(this.offset + headerLen, this.offset + headerLen + len));
    const total = headerLen + len;
    this.offset += total + ((4 - (total % 4)) % 4);
    return data;
  }

  string(): string {
    return this.bytes().toString("utf8");
  }

  longVector(): bigint[] {
    return this.vector(() => this.long());
  }

  vector<T>(item: () => T): T[] {
    const vid = this.id();
    if (vid !== VECTOR_ID) throw new Error(`TLReader: expected vector, got 0x${vid.toString(16)}`);
    const count = this.int();
    const out: T[] = [];
    for (let i = 0; i < count; i++) out.push(item());
    return out;
  }
}
