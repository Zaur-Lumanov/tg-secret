import assert from "node:assert/strict";
import { createCipheriv, randomBytes } from "node:crypto";
import { test } from "node:test";
import sharp from "sharp";
import { isDangerous, prepareFile, sanitizeFileName } from "../src/media/files.js";
import { aesIgeDecrypt, aesIgeEncrypt, decryptFile, encryptFile } from "../src/secret/crypto.js";
import type { FileMedia } from "../src/secret/media.js";
import { decodeEnvelope, encodeMessage } from "../src/secret/schema.js";
import { TLWriter } from "../src/tl/binary.js";

/** Straightforward IGE from the definition, to check the optimized implementation against. */
function referenceIgeEncrypt(plain: Buffer, key: Buffer, iv: Buffer): Buffer {
  const ecb = createCipheriv("aes-256-ecb", key, null).setAutoPadding(false);
  let prevC = iv.subarray(0, 16);
  let prevP = iv.subarray(16, 32);
  const out: Buffer[] = [];
  for (let i = 0; i < plain.length; i += 16) {
    const p = plain.subarray(i, i + 16);
    const x = Buffer.from(p.map((b, j) => b ^ prevC[j]));
    const e = ecb.update(x);
    const c = Buffer.from(e.map((b, j) => b ^ prevP[j]));
    out.push(c);
    prevC = c;
    prevP = p;
  }
  return Buffer.concat(out);
}

test("optimized AES-IGE matches the reference definition", () => {
  const key = randomBytes(32);
  const iv = randomBytes(32);
  const plain = randomBytes(16 * 50);
  const enc = aesIgeEncrypt(plain, key, iv);
  assert.deepEqual(enc, referenceIgeEncrypt(plain, key, iv));
  assert.deepEqual(aesIgeDecrypt(enc, key, iv), plain);
});

test("file encryption round-trips, pads to 16 and checks the key fingerprint", () => {
  const plain = randomBytes(1000);
  const enc = encryptFile(plain);
  assert.equal(enc.data.length, 1008);
  assert.deepEqual(decryptFile(enc.data, enc.key, enc.iv, plain.length, enc.fingerprint), plain);
  assert.throws(() => decryptFile(enc.data, enc.key, enc.iv, plain.length, enc.fingerprint ^ 1), /fingerprint mismatch/);
});

const photo: FileMedia = {
  _: "file",
  kind: "photo",
  mimeType: "image/jpeg",
  size: 12345,
  key: randomBytes(32),
  iv: randomBytes(32),
  w: 1280,
  h: 960,
  thumb: { bytes: randomBytes(700), w: 90, h: 68 },
  caption: "",
};

test("schema: photo message round-trips", () => {
  const env = decodeEnvelope(encodeMessage({ _: "message", randomId: 1n, ttl: 0, text: "sunset 🌅", media: photo }, 144));
  assert.equal(env.message._, "message");
  if (env.message._ !== "message") return;
  assert.equal(env.message.text, "sunset 🌅");
  assert.deepEqual(env.message.media, photo);
});

test("schema: document uses 64-bit size on layer 143+, 32-bit before", () => {
  const doc: FileMedia = {
    ...photo,
    kind: "document",
    mimeType: "application/pdf",
    fileName: "report ✓.pdf",
    w: undefined,
    h: undefined,
    thumb: undefined,
  };
  for (const layer of [73, 144]) {
    const body = encodeMessage({ _: "message", randomId: 2n, ttl: 5, text: "", media: doc }, layer);
    const m = decodeEnvelope(body).message;
    assert.ok(m._ === "message" && m.media?._ === "file");
    if (m._ !== "message" || m.media?._ !== "file") return;
    assert.equal(m.media.kind, "document");
    assert.equal(m.media.fileName, "report ✓.pdf");
    assert.equal(m.media.size, 12345);
    assert.deepEqual(m.media.key, doc.key);
  }
  const big = { ...doc, size: 3 * 1024 ** 3 };
  assert.throws(() => encodeMessage({ _: "message", randomId: 3n, ttl: 0, text: "", media: big }, 73));
  const m = decodeEnvelope(encodeMessage({ _: "message", randomId: 3n, ttl: 0, text: "", media: big }, 144)).message;
  assert.ok(m._ === "message" && m.media?._ === "file" && m.media.size === big.size);
});

/** Builds a decryptedMessage#91cc4674 with arbitrary raw media bytes, as another client would send it. */
function messageWithMedia(media: (w: TLWriter) => void): Buffer {
  const w = new TLWriter().id(0x91cc4674).int(1 << 9).long(9n).int(0).string("");
  media(w);
  return w.toBuffer();
}

test("schema: incoming voice note, geo point, contact and sticker are recognized", () => {
  const key = randomBytes(32), iv = randomBytes(32);
  const voice = decodeEnvelope(
    messageWithMedia((w) => {
      w.id(0x6abd9782).bytes(Buffer.alloc(0)).int(0).int(0).string("audio/ogg").long(4200n).bytes(key).bytes(iv);
      w.vector([0], () => w.id(0x9852f9c6).int(1 << 10).int(7)); // documentAttributeAudio voice, duration 7
      w.string("");
    }),
  ).message;
  assert.ok(voice._ === "message" && voice.media?._ === "file");
  if (voice._ === "message" && voice.media?._ === "file") {
    assert.equal(voice.media.kind, "voice");
    assert.equal(voice.media.duration, 7);
  }

  const geo = decodeEnvelope(messageWithMedia((w) => {
    const b = Buffer.alloc(16);
    b.writeDoubleLE(55.75, 0);
    b.writeDoubleLE(37.62, 8);
    w.id(0x35480a59).raw(b);
  })).message;
  assert.deepEqual(geo._ === "message" && geo.media, { _: "geo", lat: 55.75, long: 37.62 });

  const contact = decodeEnvelope(
    messageWithMedia((w) => w.id(0x588a0a97).string("+79990000000").string("John").string("").int(0)),
  ).message;
  assert.deepEqual(contact._ === "message" && contact.media, { _: "contact", phone: "+79990000000", firstName: "John", lastName: "" });

  const sticker = decodeEnvelope(
    messageWithMedia((w) => {
      w.id(0xfa95b0dd).long(1n).long(2n).int(0).string("image/webp").int(100);
      w.id(0x0e17e23c).string(""); // photoSizeEmpty
      w.int(2);
      w.vector([0], () => w.id(0x3a556302).string("😀").id(0xffb62b95)); // sticker, inputStickerSetEmpty
    }),
  ).message;
  assert.deepEqual(sticker._ === "message" && sticker.media, { _: "external", mimeType: "image/webp", alt: "😀", sticker: true });
});

test("sanitizeFileName blocks traversal, reserved names and bidi tricks", () => {
  assert.equal(sanitizeFileName("../../evil.txt", "x"), "evil.txt");
  assert.equal(sanitizeFileName("..\\..\\Windows\\evil.dll", "x"), "evil.dll");
  assert.equal(sanitizeFileName("CON.txt", "x"), "_CON.txt");
  assert.equal(sanitizeFileName("photo\u202egpj.exe", "x"), "photo_gpj.exe");
  assert.equal(sanitizeFileName("  ...  ", "fallback.bin"), "fallback.bin");
  assert.equal(sanitizeFileName(undefined, "photo_1.jpg"), "photo_1.jpg");
  assert.ok(isDangerous("photo_gpj.exe"));
  assert.ok(!isDangerous("report.pdf"));
});

test("prepareFile: photos become JPEG with a 90px thumbnail", async () => {
  const png = await sharp({ create: { width: 4000, height: 3000, channels: 3, background: "#3a7" } }).png().toBuffer();
  const p = await prepareFile("C:\\tmp\\big.png", png, true);
  assert.equal(p.kind, "photo");
  assert.equal(p.mimeType, "image/jpeg");
  assert.equal(p.fileName, "big.jpg");
  assert.deepEqual([p.w, p.h], [2560, 1920]);
  assert.ok(p.thumb && p.thumb.w === 90 && p.thumb.h === 68);

  const asDoc = await prepareFile("C:\\tmp\\big.png", png, false);
  assert.equal(asDoc.kind, "document");
  assert.equal(asDoc.data, png);
  assert.deepEqual([asDoc.w, asDoc.h], [4000, 3000]);
});
