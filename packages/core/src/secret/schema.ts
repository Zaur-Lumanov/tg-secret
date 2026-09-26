/**
 * Secret chat end-to-end TL schema (the subset we need).
 * Source: https://github.com/tdlib/td/blob/master/td/generate/scheme/secret_api.tl
 */
import { randomBytes } from "node:crypto";
import { TLReader, TLWriter } from "../tl/binary.js";
import { readMedia, writeMedia, type DecryptedMedia, type FileMedia } from "./media.js";

/** The layer this client implements (latest secret chat layer: 64-bit document sizes, all entity types). */
export const OUR_LAYER = 144;
/** Initial assumption about the peer's layer, per the docs. */
export const DEFAULT_PEER_LAYER = 46;

const ID = {
  decryptedMessageLayer: 0x1be31789,

  decryptedMessage8: 0x1f814f1f,
  decryptedMessageService8: 0xaa48327d,
  decryptedMessage23: 0x204d3878,
  decryptedMessageService: 0x73164160,
  decryptedMessage46: 0x36b091de,
  decryptedMessage73: 0x91cc4674,

  decryptedMessageMediaEmpty: 0x089f5c4a,

  actionSetMessageTTL: 0xa1733aec,
  actionReadMessages: 0x0c4f40be,
  actionDeleteMessages: 0x65614304,
  actionScreenshotMessages: 0x8ac1f475,
  actionFlushHistory: 0x6719e45c,
  actionResend: 0x511110b0,
  actionNotifyLayer: 0xf3048883,
  actionTyping: 0xccb27641,
  actionRequestKey: 0xf3c9611b,
  actionAcceptKey: 0x6fe1735b,
  actionAbortKey: 0xdd05ec6b,
  actionCommitKey: 0xec2e0b9b,
  actionNoop: 0xa82fdd63,
} as const;

export type DecryptedAction =
  | { _: "setTtl"; ttl: number }
  | { _: "read"; randomIds: bigint[] }
  | { _: "delete"; randomIds: bigint[] }
  | { _: "screenshot"; randomIds: bigint[] }
  | { _: "flushHistory" }
  | { _: "resend"; startSeqNo: number; endSeqNo: number }
  | { _: "notifyLayer"; layer: number }
  | { _: "typing" }
  | { _: "requestKey"; exchangeId: bigint; gA: Buffer }
  | { _: "acceptKey"; exchangeId: bigint; gB: Buffer; fingerprint: bigint }
  | { _: "abortKey"; exchangeId: bigint }
  | { _: "commitKey"; exchangeId: bigint; fingerprint: bigint }
  | { _: "noop" }
  | { _: "unknown"; constructorId: number };

export type DecryptedMessage =
  | { _: "message"; randomId: bigint; ttl: number; text: string; media?: DecryptedMedia; silent?: boolean }
  | { _: "service"; randomId: bigint; action: DecryptedAction };

export interface LayerInfo {
  layer: number;
  inSeqNo: number;
  outSeqNo: number;
}

export interface DecryptedEnvelope {
  /** Absent for legacy layer-8 messages sent without a DecryptedMessageLayer wrapper. */
  layer?: LayerInfo;
  message: DecryptedMessage;
}

// ---------------------------------------------------------------- encoding

function writeAction(w: TLWriter, a: DecryptedAction): void {
  switch (a._) {
    case "setTtl": w.id(ID.actionSetMessageTTL).int(a.ttl); break;
    case "read": w.id(ID.actionReadMessages).longVector(a.randomIds); break;
    case "delete": w.id(ID.actionDeleteMessages).longVector(a.randomIds); break;
    case "screenshot": w.id(ID.actionScreenshotMessages).longVector(a.randomIds); break;
    case "flushHistory": w.id(ID.actionFlushHistory); break;
    case "resend": w.id(ID.actionResend).int(a.startSeqNo).int(a.endSeqNo); break;
    case "notifyLayer": w.id(ID.actionNotifyLayer).int(a.layer); break;
    case "typing": w.id(ID.actionTyping).id(0x16bf744e); break;
    case "requestKey": w.id(ID.actionRequestKey).long(a.exchangeId).bytes(a.gA); break;
    case "acceptKey": w.id(ID.actionAcceptKey).long(a.exchangeId).bytes(a.gB).long(a.fingerprint); break;
    case "abortKey": w.id(ID.actionAbortKey).long(a.exchangeId); break;
    case "commitKey": w.id(ID.actionCommitKey).long(a.exchangeId).long(a.fingerprint); break;
    case "noop": w.id(ID.actionNoop); break;
    case "unknown": throw new Error("Cannot encode unknown action");
  }
}

/** Serializes a DecryptedMessage using constructors understood by a peer on `peerLayer`. */
export function encodeMessage(m: DecryptedMessage, peerLayer: number): Buffer {
  const w = new TLWriter();
  if (m._ === "service") {
    w.id(ID.decryptedMessageService).long(m.randomId);
    writeAction(w, m.action);
  } else if (peerLayer >= 46) {
    const media = outgoingMedia(m.media);
    const flags = (m.silent && peerLayer >= 73 ? 1 << 5 : 0) | (media ? 1 << 9 : 0);
    w.id(peerLayer >= 73 ? ID.decryptedMessage73 : ID.decryptedMessage46);
    w.int(flags).long(m.randomId).int(m.ttl).string(m.text);
    if (media) writeMedia(w, media, peerLayer);
  } else {
    if (m.media) throw new Error("The peer's protocol version is too old for files");
    w.id(ID.decryptedMessage23).long(m.randomId).int(m.ttl).string(m.text).id(ID.decryptedMessageMediaEmpty);
  }
  return w.toBuffer();
}

function outgoingMedia(media: DecryptedMedia | undefined): FileMedia | undefined {
  if (media && media._ !== "file") throw new Error(`Sending media of type ${media._} is not supported`);
  return media;
}

export function encodeLayer(info: LayerInfo, messageBytes: Buffer): Buffer {
  return new TLWriter()
    .id(ID.decryptedMessageLayer)
    .bytes(randomBytes(16)) // docs: at least 15 random bytes
    .int(info.layer)
    .int(info.inSeqNo)
    .int(info.outSeqNo)
    .raw(messageBytes)
    .toBuffer();
}

// ---------------------------------------------------------------- decoding

function readAction(r: TLReader): DecryptedAction {
  const id = r.id();
  switch (id) {
    case ID.actionSetMessageTTL: return { _: "setTtl", ttl: r.int() };
    case ID.actionReadMessages: return { _: "read", randomIds: r.longVector() };
    case ID.actionDeleteMessages: return { _: "delete", randomIds: r.longVector() };
    case ID.actionScreenshotMessages: return { _: "screenshot", randomIds: r.longVector() };
    case ID.actionFlushHistory: return { _: "flushHistory" };
    case ID.actionResend: return { _: "resend", startSeqNo: r.int(), endSeqNo: r.int() };
    case ID.actionNotifyLayer: return { _: "notifyLayer", layer: r.int() };
    case ID.actionTyping: return { _: "typing" };
    case ID.actionRequestKey: return { _: "requestKey", exchangeId: r.long(), gA: r.bytes() };
    case ID.actionAcceptKey: return { _: "acceptKey", exchangeId: r.long(), gB: r.bytes(), fingerprint: r.long() };
    case ID.actionAbortKey: return { _: "abortKey", exchangeId: r.long() };
    case ID.actionCommitKey: return { _: "commitKey", exchangeId: r.long(), fingerprint: r.long() };
    case ID.actionNoop: return { _: "noop" };
    default: return { _: "unknown", constructorId: id };
  }
}

/**
 * Reads a DecryptedMessage. Entities, via_bot_name, reply_to and grouped_id come after
 * the media and are not needed, so decoding stops there.
 */
function readMessage(r: TLReader): DecryptedMessage {
  const id = r.id();
  switch (id) {
    case ID.decryptedMessage73:
    case ID.decryptedMessage46: {
      const flags = r.int();
      const randomId = r.long();
      const ttl = r.int();
      const text = r.string();
      const media = flags & (1 << 9) ? readMedia(r) : undefined;
      return { _: "message", randomId, ttl, text, media, silent: (flags & (1 << 5)) !== 0 };
    }
    case ID.decryptedMessage23: {
      const randomId = r.long();
      const ttl = r.int();
      const text = r.string();
      return { _: "message", randomId, ttl, text, media: readMedia(r) };
    }
    case ID.decryptedMessage8: {
      const randomId = r.long();
      r.bytes(); // random_bytes
      const text = r.string();
      return { _: "message", randomId, ttl: 0, text, media: readMedia(r) };
    }
    case ID.decryptedMessageService:
      return { _: "service", randomId: r.long(), action: readAction(r) };
    case ID.decryptedMessageService8: {
      const randomId = r.long();
      r.bytes();
      return { _: "service", randomId, action: readAction(r) };
    }
    default:
      throw new Error(`Unknown DecryptedMessage constructor 0x${id.toString(16)}`);
  }
}

export function decodeEnvelope(payload: Buffer): DecryptedEnvelope {
  const r = new TLReader(payload);
  if (payload.readUInt32LE(0) === ID.decryptedMessageLayer) {
    r.id();
    r.bytes(); // random_bytes
    const layer = r.int();
    const inSeqNo = r.int();
    const outSeqNo = r.int();
    return { layer: { layer, inSeqNo, outSeqNo }, message: readMessage(r) };
  }
  return { message: readMessage(r) };
}
