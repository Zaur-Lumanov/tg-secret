import { existsSync } from "node:fs";
import { basename, extname, join } from "node:path";
import type { FileKind, Thumb } from "../secret/media.js";

const MIME_BY_EXT: Record<string, string> = {
  ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp",
  ".gif": "image/gif", ".bmp": "image/bmp", ".heic": "image/heic", ".svg": "image/svg+xml",
  ".mp4": "video/mp4", ".mov": "video/quicktime", ".mkv": "video/x-matroska", ".webm": "video/webm",
  ".mp3": "audio/mpeg", ".ogg": "audio/ogg", ".oga": "audio/ogg", ".m4a": "audio/mp4", ".wav": "audio/wav",
  ".flac": "audio/flac", ".pdf": "application/pdf", ".txt": "text/plain", ".zip": "application/zip",
  ".json": "application/json", ".doc": "application/msword", ".xls": "application/vnd.ms-excel",
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ".tgs": "application/x-tgsticker",
};

const EXT_BY_MIME: Record<string, string> = {
  "image/jpeg": ".jpg", "video/quicktime": ".mov", "audio/mpeg": ".mp3", "audio/ogg": ".ogg", "audio/mp4": ".m4a",
  ...Object.fromEntries(Object.entries(MIME_BY_EXT).map(([ext, mime]) => [mime, ext])),
};

export const mimeFromPath = (path: string): string =>
  MIME_BY_EXT[extname(path).toLowerCase()] ?? "application/octet-stream";

/**
 * Extensions that execute code (or point to something that does) when "opened".
 * Files received from the peer with these extensions are never opened automatically.
 */
const DANGEROUS_EXT = new Set([
  ".exe", ".com", ".scr", ".pif", ".bat", ".cmd", ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse",
  ".wsf", ".wsh", ".hta", ".msi", ".msp", ".mst", ".lnk", ".url", ".reg", ".cpl", ".jar", ".application",
  ".appref-ms", ".gadget", ".msc", ".inf", ".scf", ".dll", ".sys", ".iso", ".img", ".vhd", ".vhdx",
  ".chm", ".xll", ".xlam", ".docm", ".xlsm", ".pptm", ".library-ms", ".settingcontent-ms", ".search-ms",
  ".sh", ".bash", ".command", ".app", ".desktop", ".run", ".py", ".pyw", ".pl", ".rb", ".apk",
]);

export const isDangerous = (path: string): boolean => DANGEROUS_EXT.has(extname(path).toLowerCase());

const WINDOWS_RESERVED = /^(con|prn|aux|nul|com\d|lpt\d)$/i;

/**
 * Makes a peer-controlled file name safe to use inside our downloads directory:
 * no path separators, no traversal, no reserved or invisible characters.
 */
export function sanitizeFileName(name: string | undefined, fallback: string): string {
  let n = basename((name ?? "").replace(/\\/g, "/"))
    .normalize("NFC")
    // control chars, Windows-forbidden chars and bidi overrides (used to fake extensions: "exe.pdf")
    .replace(/[\u0000-\u001f\u007f<>:"/\\|?*‪-‮⁦-⁩‎‏]/g, "_")
    .replace(/^[.\s]+|[.\s]+$/g, "");
  if (!n) n = fallback;
  const ext = extname(n);
  const stem = n.slice(0, n.length - ext.length);
  if (WINDOWS_RESERVED.test(stem)) n = `_${n}`;
  if (n.length > 120) n = stem.slice(0, 120 - ext.length) + ext;
  return n;
}

export function extensionFor(mimeType: string): string {
  return EXT_BY_MIME[mimeType] ?? "";
}

/** Adds " (1)", " (2)"… before the extension until the path is free. */
export function uniquePath(dir: string, name: string): string {
  const ext = extname(name);
  const stem = name.slice(0, name.length - ext.length);
  let p = join(dir, name);
  for (let i = 1; existsSync(p); i++) p = join(dir, `${stem} (${i})${ext}`);
  return p;
}

const PHOTO_MAX_SIDE = 2560;
const THUMB_SIDE = 90;
const PHOTO_INPUT = new Set(["image/jpeg", "image/png", "image/webp", "image/bmp", "image/heic"]);

export interface PreparedFile {
  kind: FileKind;
  data: Buffer;
  mimeType: string;
  fileName: string;
  w?: number;
  h?: number;
  thumb?: Thumb;
}

type Sharp = typeof import("sharp").default;

let sharpModule: Promise<Sharp | undefined> | undefined;

/** sharp is an optional dependency: without it photos are sent as documents, without previews. */
function loadSharp(): Promise<Sharp | undefined> {
  sharpModule ??= import("sharp").then(
    (m) => m.default,
    () => undefined,
  );
  return sharpModule;
}

async function makeThumb(sharp: Sharp, input: Buffer): Promise<Thumb> {
  const { data, info } = await sharp(input)
    .rotate()
    .resize(THUMB_SIDE, THUMB_SIDE, { fit: "inside" })
    .jpeg({ quality: 70 })
    .toBuffer({ resolveWithObject: true });
  return { bytes: data, w: info.width, h: info.height };
}

/**
 * Prepares a local file for sending.
 * asPhoto: re-encode as JPEG (max 2560px) with a 90px thumbnail, like official clients do.
 * Otherwise the file is sent unchanged as a document; images still get a thumbnail.
 */
export async function prepareFile(path: string, data: Buffer, asPhoto: boolean): Promise<PreparedFile> {
  const mimeType = mimeFromPath(path);
  const fileName = basename(path);
  const sharp = await loadSharp();
  if (!sharp) return { kind: "document", data, mimeType, fileName };

  if (asPhoto && PHOTO_INPUT.has(mimeType)) {
    const { data: jpeg, info } = await sharp(data)
      .rotate() // apply EXIF orientation
      .resize(PHOTO_MAX_SIDE, PHOTO_MAX_SIDE, { fit: "inside", withoutEnlargement: true })
      .jpeg({ quality: 87 })
      .toBuffer({ resolveWithObject: true });
    return {
      kind: "photo",
      data: jpeg,
      mimeType: "image/jpeg",
      fileName: fileName.replace(/\.[^.]+$/, "") + ".jpg",
      w: info.width,
      h: info.height,
      thumb: await makeThumb(sharp, jpeg),
    };
  }

  if (mimeType.startsWith("image/") && mimeType !== "image/svg+xml") {
    try {
      const meta = await sharp(data).metadata();
      return { kind: "document", data, mimeType, fileName, w: meta.width, h: meta.height, thumb: await makeThumb(sharp, data) };
    } catch {
      // not decodable by sharp — send without preview
    }
  }
  return { kind: "document", data, mimeType, fileName };
}
