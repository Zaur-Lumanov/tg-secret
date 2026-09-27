import assert from "node:assert/strict";
import { constants, generateKeyPairSync, privateDecrypt, publicEncrypt, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { CardTransport } from "../src/security/pcsc.js";
import { oaepDecodeSha1, Piv, WrongPinError } from "../src/security/piv.js";
import { parseFailure } from "../src/security/powershell.js";
import { Vault, WrongPasswordError } from "../src/security/vault.js";
import { unlockVault } from "../src/security/password.js";
import type { NoticeLevel, Prompts } from "../src/prompts.js";
import { maskArgs, parsePivInfo } from "../src/security/yubikey.js";

const FAST_KDF = { memory: 1024, passes: 1, parallelism: 1 };
const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });

/**
 * A fake YubiKey PIV applet: select, serial, PIN with retry counter, RSA-2048 GENERAL
 * AUTHENTICATE with command chaining and a response split by 61xx, like the real card.
 */
class FakeYubikey implements CardTransport {
  pinRetries = 3;
  verified = false;
  touched = 0;
  private chained: Buffer[] = [];
  private pending = Buffer.alloc(0);

  constructor(private readonly pin = "654321") {}

  async transmit(apdu: Buffer): Promise<Buffer> {
    const ok = (data = Buffer.alloc(0)) => Buffer.concat([data, Buffer.from([0x90, 0x00])]);
    const [cla, ins, p1, p2] = apdu;
    if (ins === 0xa4) return ok();
    if (ins === 0xf8) return ok(Buffer.from([0x01, 0x54, 0xd6, 0xde])); // 22337246
    if (ins === 0xc0) {
      const part = this.pending.subarray(0, 256);
      this.pending = this.pending.subarray(256);
      return Buffer.concat([part, this.pending.length ? Buffer.from([0x61, Math.min(this.pending.length, 0xff)]) : Buffer.from([0x90, 0x00])]);
    }
    if (ins === 0x20) {
      if (this.pinRetries === 0) return Buffer.from([0x69, 0x83]);
      const given = apdu.subarray(5, 13);
      const expected = Buffer.concat([Buffer.from(this.pin), Buffer.alloc(8 - this.pin.length, 0xff)]);
      if (given.equals(expected)) {
        this.pinRetries = 3;
        this.verified = true;
        return ok();
      }
      this.pinRetries--;
      return Buffer.from([0x63, 0xc0 | this.pinRetries]);
    }
    if (ins === 0x87) {
      assert.equal(p1, 0x07, "RSA-2048 algorithm");
      assert.equal(p2, 0x9d, "slot 9D");
      this.chained.push(apdu.subarray(5, 5 + apdu[4]));
      if (cla === 0x10) return ok();
      const body = Buffer.concat(this.chained);
      this.chained = [];
      if (!this.verified) return Buffer.from([0x69, 0x82]);
      this.touched++;
      // 7C 82 01 06 | 82 00 | 81 82 01 00 <256 bytes>
      const input = body.subarray(body.length - 256);
      const raw = privateDecrypt({ key: privateKey, padding: constants.RSA_NO_PADDING }, input);
      const resp = Buffer.concat([Buffer.from([0x7c, 0x82, 0x01, 0x04, 0x82, 0x82, 0x01, 0x00]), raw]);
      this.pending = resp.subarray(256);
      return Buffer.concat([resp.subarray(0, 256), Buffer.from([0x61, this.pending.length])]);
    }
    return Buffer.from([0x6d, 0x00]);
  }
}

test("OAEP-SHA1 decoding matches Node's RSA-OAEP", () => {
  const kek = randomBytes(32);
  const ct = publicEncrypt({ key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" }, kek);
  const em = privateDecrypt({ key: privateKey, padding: constants.RSA_NO_PADDING }, ct);
  assert.deepEqual(oaepDecodeSha1(em), kek);
  const broken = Buffer.from(em);
  broken[40] ^= 1;
  assert.throws(() => oaepDecodeSha1(broken));
});

test("PIV: serial, PIN check, chained RSA decryption with 61xx continuation", async () => {
  const card = new FakeYubikey();
  const piv = new Piv(card);
  await piv.select();
  assert.equal(await piv.serial(), 22337246);

  await assert.rejects(piv.verifyPin("111111"), (e: unknown) => e instanceof WrongPinError && e.retriesLeft === 2);
  await piv.verifyPin("654321");

  const kek = randomBytes(32);
  const ct = publicEncrypt({ key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" }, kek);
  const em = await piv.rsaRaw(0x9d, ct);
  assert.deepEqual(oaepDecodeSha1(em), kek);
  assert.equal(card.touched, 1);
});

test("PIV: blocked PIN is reported as such", async () => {
  const card = new FakeYubikey();
  card.pinRetries = 0;
  await assert.rejects(new Piv(card).verifyPin("654321"), /PIN is blocked/);
});

test("parsePivInfo on real ykman output", () => {
  const fresh = parsePivInfo(`PIV version:              5.4.3
PIN tries remaining:      3/3
PUK tries remaining:      3/3
Management key algorithm: TDES
WARNING: Using default PIN!
WARNING: Using default PUK!
WARNING: Using default Management key!
CHUID: 3019d4e7
CCC:   No data available`);
  assert.deepEqual(fresh, {
    defaultPin: true,
    defaultPuk: true,
    defaultManagementKey: true,
    managementKeyProtected: false,
    pinTriesLeft: 3,
    usedSlots: new Set(),
  });

  const used = parsePivInfo(`PIV version:              5.4.3
PIN tries remaining:      3/3
Slot 9D (KEY_MANAGEMENT):
  Private key type: RSA2048
Slot 82 (RETIRED1):
  Private key type: RSA2048`);
  assert.deepEqual(used.usedSlots, new Set(["9d", "82"]));
  assert.equal(parsePivInfo("Management key is stored on the YubiKey, protected by PIN.").managementKeyProtected, true);
  assert.equal(used.defaultPin, false);
});

test("vault slots: hardware slot unlocks, password change keeps it, removal works", () => {
  const dir = mkdtempSync(join(tmpdir(), "tgs-"));
  const path = join(dir, "vault.json");
  const vault = Vault.create(path, "password-1", FAST_KDF);
  vault.writeFile(join(dir, "data.enc"), "session", Buffer.from("auth key"));

  const kek = randomBytes(32);
  const slot = vault.addSlot(
    { type: "yubikey-piv", label: "main", serial: 1, pivSlot: "9d", certThumbprint: "AA", encryptedKek: "" },
    kek,
  );
  const viaKey = Vault.unlockWithKek(path, slot.id, kek);
  assert.equal(viaKey.readFile(join(dir, "data.enc"), "session").toString(), "auth key");
  assert.throws(() => Vault.unlockWithKek(path, slot.id, randomBytes(32)), /does not match the vault/);

  vault.changePassword("password-1", "password-2", FAST_KDF);
  assert.ok(Vault.unlockWithKek(path, slot.id, kek), "hardware slot survives a password change");
  assert.throws(() => Vault.unlock(path, "password-1"), WrongPasswordError);

  Vault.updateSlotMeta(path, slot.id, { pinEntry: "windows" });
  assert.equal((Vault.slots(path)[1] as { pinEntry?: string }).pinEntry, "windows");

  vault.removeSlot(slot.id);
  assert.equal(Vault.slots(path).length, 1);
  assert.throws(() => vault.removeSlot("password"), /password can't be removed/);
});

test("vault: the version 1 format is still readable", () => {
  const dir = mkdtempSync(join(tmpdir(), "tgs-"));
  const path = join(dir, "vault.json");
  Vault.create(path, "password-1", FAST_KDF);
  const v2 = JSON.parse(readFileSync(path, "utf8"));
  const pw = v2.slots[0];
  writeFileSync(path, JSON.stringify({ version: 1, kdf: pw.kdf, key: pw.key }));
  assert.ok(Vault.unlock(path, "password-1"));
  assert.equal(Vault.slots(path)[0].type, "password");
});

test("PowerShell failures: our CODE line is found among CLIXML progress noise", () => {
  const stderr = [
    "#< CLIXML",
    '<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress" RefId="0"></Obj></Objs>',
    "HELLO_USERCANCELED: UserCanceled",
    '<Objs Version="1.1.0.1"><Obj S="progress" RefId="1"></Obj></Objs>',
  ].join("\r\n");
  const e = parseFailure(stderr, 2);
  assert.equal(e.code, "HELLO_USERCANCELED");
  assert.equal(parseFailure("#< CLIXML\r\n<Objs/>\r\nsomething broke", 1).message, "something broke");
});

test("secrets passed to ykman never show up in printed commands", () => {
  assert.deepEqual(
    maskArgs(["piv", "access", "change-pin", "--pin", "123456", "--new-pin", "76543210"]),
    ["piv", "access", "change-pin", "--pin", "***", "--new-pin", "***"],
  );
  assert.deepEqual(maskArgs(["--management-key", "0102", "--protect", "--force"]), ["--management-key", "***", "--protect", "--force"]);
});

test("an empty password (a stray Enter) is asked again and doesn't count as a wrong attempt", async () => {
  const path = join(mkdtempSync(join(tmpdir(), "tge-")), "vault.json");
  Vault.create(path, "right-password", { memory: 1024, passes: 1, parallelism: 1 });
  const answers = ["", "", "wrong-pass", "", "", "right-password"];
  const errors: string[] = [];
  const prompts = {
    secret: async () => answers.shift()!,
    notice: (level: NoticeLevel, ...lines: string[]) => level === "error" && errors.push(...lines),
  } as unknown as Prompts;
  const vault = await unlockVault(prompts, path, "79990000000");
  assert.ok(!vault.locked);
  assert.deepEqual(errors, ["Wrong password (1/3)"], "only the real wrong password counted");
  assert.equal(answers.length, 0);
});
