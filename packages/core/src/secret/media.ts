/**
 * DecryptedMessageMedia and related types of the secret chat schema.
 * Source: https://github.com/tdlib/td/blob/master/td/generate/scheme/secret_api.tl
 */
import type { TLReader, TLWriter } from "../tl/binary.js";

export interface Thumb {
  bytes: Buffer;
  w: number;
  h: number;
}

export type FileKind = "photo" | "video" | "audio" | "voice" | "round" | "gif" | "sticker" | "document";

/** Media whose content is an encrypted file attached to the message. */
export interface FileMedia {
  _: "file";
  kind: FileKind;
  mimeType: string;
  size: number;
  key: Buffer;
  iv: Buffer;
  fileName?: string;
  w?: number;
  h?: number;
  duration?: number;
  thumb?: Thumb;
  caption: string;
}

export type DecryptedMedia =
  | FileMedia
  | { _: "geo"; lat: number; long: number }
  | { _: "venue"; lat: number; long: number; title: string; address: string }
  | { _: "contact"; phone: string; firstName: string; lastName: string }
  | { _: "webpage"; url: string }
  /** a sticker/GIF from Telegram servers (not end-to-end encrypted, not downloadable here) */
  | { _: "external"; mimeType: string; alt?: string; sticker: boolean }
  | { _: "unknown"; constructorId: number };

const ID = {
  empty: 0x089f5c4a,
  photo8: 0x32798a8c,
  video8: 0x4cee6ef3,
  geoPoint: 0x35480a59,
  contact: 0x588a0a97,
  document8: 0xb095434b,
  audio8: 0x6080758f,
  video23: 0x524a415d,
  audio23: 0x57e0a9cb,
  externalDocument: 0xfa95b0dd,
  photo: 0xf1fa8d78,
  video: 0x970c8c0e,
  document46: 0x7afe8ae2,
  venue: 0x8a0df56f,
  webPage: 0xe50511d8,
  document143: 0x6abd9782,
} as const;

const ATTR = {
  imageSize: 0x6c37c15c,
  animated: 0x11b58939,
  sticker23: 0xfb0a5727,
  video23: 0x5910cccb,
  audio23: 0x051448e5,
  filename: 0x15590068,
  audio45: 0xded218e0,
  sticker: 0x3a556302,
  audio: 0x9852f9c6,
  video: 0x0ef02ce6,
} as const;

interface Attributes {
  fileName?: string;
  w?: number;
  h?: number;
  duration?: number;
  animated?: boolean;
  sticker?: boolean;
  alt?: string;
  voice?: boolean;
  audio?: boolean;
  video?: boolean;
  round?: boolean;
}

function readAttributes(r: TLReader): Attributes {
  const a: Attributes = {};
  r.vector(() => {
    const id = r.id();
    switch (id) {
      case ATTR.imageSize: a.w = r.int(); a.h = r.int(); break;
      case ATTR.animated: a.animated = true; break;
      case ATTR.sticker23: a.sticker = true; break;
      case ATTR.video23: a.video = true; a.duration = r.int(); a.w = r.int(); a.h = r.int(); break;
      case ATTR.audio23: a.audio = true; a.duration = r.int(); break;
      case ATTR.filename: a.fileName = r.string(); break;
      case ATTR.audio45: a.audio = true; a.duration = r.int(); r.string(); r.string(); break;
      case ATTR.sticker: {
        a.sticker = true;
        a.alt = r.string();
        const set = r.id();
        if (set === 0x861cc8a0) r.string(); // inputStickerSetShortName
        break;
      }
      case ATTR.audio: {
        const flags = r.int();
        a.audio = true;
        a.voice = (flags & (1 << 10)) !== 0;
        a.duration = r.int();
        if (flags & 1) r.string();
        if (flags & 2) r.string();
        if (flags & 4) r.bytes();
        break;
      }
      case ATTR.video: {
        const flags = r.int();
        a.video = true;
        a.round = (flags & 1) !== 0;
        a.duration = r.int();
        a.w = r.int();
        a.h = r.int();
        break;
      }
      default:
        throw new Error(`Unknown DocumentAttribute 0x${id.toString(16)}`);
    }
  });
  return a;
}

function documentKind(mimeType: string, a: Attributes): FileKind {
  if (a.sticker) return "sticker";
  if (a.round) return "round";
  if (a.voice) return "voice";
  if (a.animated || mimeType === "image/gif") return "gif";
  if (a.video) return "video";
  if (a.audio) return "audio";
  return "document";
}

const thumbOf = (bytes: Buffer, w: number, h: number): Thumb | undefined =>
  bytes.length ? { bytes, w, h } : undefined;

/** PhotoSize of an external document: we only need to consume it. */
function skipPhotoSize(r: TLReader): void {
  const id = r.id();
  const skipLocation = () => {
    if (r.id() === 0x53d69076) r.int(); // fileLocation has dc_id first
    r.long();
    r.int();
    r.long();
  };
  if (id === 0x0e17e23c) {
    r.string();
  } else if (id === 0x77bfb61b) {
    r.string(); skipLocation(); r.int(); r.int(); r.int();
  } else if (id === 0xe9a734fa) {
    r.string(); skipLocation(); r.int(); r.int(); r.bytes();
  } else {
    throw new Error(`Unknown PhotoSize 0x${id.toString(16)}`);
  }
}

/** Returns undefined for decryptedMessageMediaEmpty. */
export function readMedia(r: TLReader): DecryptedMedia | undefined {
  const id = r.id();
  switch (id) {
    case ID.empty:
      return undefined;

    case ID.photo8:
    case ID.photo: {
      const thumb = r.bytes(), tw = r.int(), th = r.int(), w = r.int(), h = r.int(), size = r.int();
      const key = r.bytes(), iv = r.bytes();
      const caption = id === ID.photo ? r.string() : "";
      return { _: "file", kind: "photo", mimeType: "image/jpeg", size, key, iv, w, h, thumb: thumbOf(thumb, tw, th), caption };
    }

    case ID.video8:
    case ID.video23:
    case ID.video: {
      const thumb = r.bytes(), tw = r.int(), th = r.int(), duration = r.int();
      const mimeType = id === ID.video8 ? "video/mp4" : r.string();
      const w = r.int(), h = r.int(), size = r.int(), key = r.bytes(), iv = r.bytes();
      const caption = id === ID.video ? r.string() : "";
      return { _: "file", kind: "video", mimeType, size, key, iv, w, h, duration, thumb: thumbOf(thumb, tw, th), caption };
    }

    case ID.audio8:
    case ID.audio23: {
      const duration = r.int();
      const mimeType = id === ID.audio8 ? "audio/ogg" : r.string();
      const size = r.int(), key = r.bytes(), iv = r.bytes();
      return { _: "file", kind: "voice", mimeType, size, key, iv, duration, caption: "" };
    }

    case ID.document8: {
      const thumb = r.bytes(), tw = r.int(), th = r.int();
      const fileName = r.string(), mimeType = r.string(), size = r.int(), key = r.bytes(), iv = r.bytes();
      return { _: "file", kind: "document", mimeType, size, key, iv, fileName, thumb: thumbOf(thumb, tw, th), caption: "" };
    }

    case ID.document46:
    case ID.document143: {
      const thumb = r.bytes(), tw = r.int(), th = r.int(), mimeType = r.string();
      const size = id === ID.document143 ? Number(r.long()) : r.int();
      const key = r.bytes(), iv = r.bytes(), a = readAttributes(r), caption = r.string();
      return {
        _: "file",
        kind: documentKind(mimeType, a),
        mimeType,
        size,
        key,
        iv,
        fileName: a.fileName,
        w: a.w,
        h: a.h,
        duration: a.duration,
        thumb: thumbOf(thumb, tw, th),
        caption,
      };
    }

    case ID.externalDocument: {
      r.long(); r.long(); r.int(); // id, access_hash, date
      const mimeType = r.string();
      r.int(); // size
      skipPhotoSize(r);
      r.int(); // dc_id
      const a = readAttributes(r);
      return { _: "external", mimeType, alt: a.alt, sticker: !!a.sticker };
    }

    case ID.geoPoint:
      return { _: "geo", lat: r.double(), long: r.double() };
    case ID.venue: {
      const lat = r.double(), long = r.double(), title = r.string(), address = r.string();
      r.string(); r.string(); // provider, venue_id
      return { _: "venue", lat, long, title, address };
    }
    case ID.contact: {
      const phone = r.string(), firstName = r.string(), lastName = r.string();
      r.int();
      return { _: "contact", phone, firstName, lastName };
    }
    case ID.webPage:
      return { _: "webpage", url: r.string() };

    default:
      return { _: "unknown", constructorId: id };
  }
}

/**
 * Writes an outgoing file media. Photos use decryptedMessageMediaPhoto, everything else
 * is sent as a document (with 64-bit size for peers on layer >= 143).
 */
export function writeMedia(w: TLWriter, m: FileMedia, peerLayer: number): void {
  if (peerLayer < 46) throw new Error("The peer's protocol version is too old for files");
  const thumb = m.thumb ?? { bytes: Buffer.alloc(0), w: 0, h: 0 };

  if (m.kind === "photo") {
    w.id(ID.photo).bytes(thumb.bytes).int(thumb.w).int(thumb.h).int(m.w ?? 0).int(m.h ?? 0).int(m.size);
    w.bytes(m.key).bytes(m.iv).string(m.caption);
    return;
  }

  const big = peerLayer >= 143;
  if (!big && m.size > 0x7fffffff) throw new Error("The file is too large for the peer's protocol version");
  w.id(big ? ID.document143 : ID.document46).bytes(thumb.bytes).int(thumb.w).int(thumb.h).string(m.mimeType);
  if (big) w.long(BigInt(m.size));
  else w.int(m.size);
  w.bytes(m.key).bytes(m.iv);

  const attrs: ((w: TLWriter) => void)[] = [];
  if (m.w && m.h) attrs.push((x) => x.id(ATTR.imageSize).int(m.w!).int(m.h!));
  if (m.fileName) attrs.push((x) => x.id(ATTR.filename).string(m.fileName!));
  w.vector(attrs, (a) => a(w));
  w.string(m.caption);
}
