// Client-side wiring for voice/video calls: the REST signaling calls live
// on `api` (see api.ts's "calls" section); this module is the streaming
// half — state events (ringing/connected/participant-joined/hangup) and
// VP8 video/screen-share frames the daemon pushes rather than answers.
//
// The webview can't open `GET /calls/:call_id/ws` itself (see
// `src-tauri/src/call_stream_bridge.rs`'s module doc for why — its
// WebSocket handshake always carries an `Origin` header the daemon's
// `reject_browser_origin` middleware rejects). Instead, the Tauri
// Rust process dials that WebSocket and re-emits what it receives as
// `call-event`/`call-frame` Tauri events; `subscribeToCallStream` below
// is the JS-side listener for those events.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export type CallEvent =
  | { type: "connected" }
  | { type: "participant_joined"; tag: number }
  | { type: "participant_left"; tag: number }
  | { type: "hangup" };

/** Matches `bh_api::call_stream::FrameKind`'s `u8` tag. */
export const FrameKind = {
  RemoteVideo: 0,
  RemoteScreen: 1,
  LocalVideo: 2,
  LocalScreen: 3,
} as const;
export type FrameKind = (typeof FrameKind)[keyof typeof FrameKind];

export interface CallFrame {
  kind: FrameKind;
  /** Raw, already-decrypted VP8 bitstream for one encoded frame — decode
   *  locally (e.g. via `VideoDecoder` from the WebCodecs API); this
   *  daemon deliberately never decodes VP8 itself (no audited safe-Rust
   *  decoder — see `bh-calls::video`'s module doc). */
  bytes: Uint8Array;
}

export interface CallStreamHandlers {
  onEvent?: (event: CallEvent) => void;
  onFrame?: (frame: CallFrame) => void;
}

interface CallEventPayload {
  call_id: string;
  event: CallEvent;
}

interface CallFramePayload {
  call_id: string;
  kind: FrameKind;
  bytes_b64: string;
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * Opens the stream for `callId` and forwards its events/frames to
 * `handlers` until the returned function is called (or the call ends and
 * the daemon closes its side). Safe to call for multiple calls at once —
 * each subscription filters on `call_id` before invoking its own
 * `handlers`, so one call's frames never reach another's callbacks.
 *
 * Call this only once the call actually exists on the daemon (i.e. after
 * `api.startCall`/`api.acceptCall`/`api.startGroupCall`) — `GET
 * /calls/:call_id/ws` 404s for a call id that was never created. Because
 * `complete_call`/`accept_call`/`start_group_call` may have already
 * recorded their first state event (e.g. `Connected`) *before* this
 * subscription opens, the daemon replays that last-known state as the
 * very first message — `onEvent` is guaranteed to fire at least once
 * with the call's current state, not just future transitions.
 */
export async function subscribeToCallStream(
  callId: string,
  handlers: CallStreamHandlers,
): Promise<() => Promise<void>> {
  const unlistenEvent = await listen<CallEventPayload>("call-event", (msg) => {
    if (msg.payload.call_id === callId) handlers.onEvent?.(msg.payload.event);
  });
  const unlistenFrame = await listen<CallFramePayload>("call-frame", (msg) => {
    if (msg.payload.call_id === callId) {
      handlers.onFrame?.({
        kind: msg.payload.kind,
        bytes: base64ToBytes(msg.payload.bytes_b64),
      });
    }
  });

  await invoke("subscribe_call_stream", { callId });

  return async () => {
    unlistenEvent();
    unlistenFrame();
    await invoke("unsubscribe_call_stream", { callId });
  };
}

/** RFC 6386 §9.1: a VP8 frame tag's low bit is the frame type — 0 for a
 *  key frame, 1 for an interframe. `bh-calls`' encoder emits this exact
 *  raw bitstream per frame with no extra framing on top. */
function isVp8KeyFrame(bytes: Uint8Array): boolean {
  return bytes.length > 0 && (bytes[0] & 0x1) === 0;
}

/**
 * Decodes a stream of raw VP8 frames (one full encoded frame per
 * `CallFrame`, as `bh-calls`' capture pipeline produces them) onto a
 * `<canvas>` via the browser's WebCodecs `VideoDecoder` — the client-side
 * half of the "the daemon never decodes VP8 itself" split (no audited
 * safe-Rust decoder exists, see `bh-calls::video`'s module doc).
 */
export class Vp8CanvasRenderer {
  private readonly decoder: VideoDecoder;
  private readonly ctx: CanvasRenderingContext2D;
  private haveKeyFrame = false;
  private closed = false;

  constructor(private readonly canvas: HTMLCanvasElement) {
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new Error("canvas 2d context unavailable");
    this.ctx = ctx;
    this.decoder = new VideoDecoder({
      output: (frame) => this.draw(frame),
      error: (err) => console.error("VP8 decode error", err),
    });
    this.decoder.configure({ codec: "vp8" });
  }

  private draw(frame: VideoFrame): void {
    if (this.canvas.width !== frame.displayWidth || this.canvas.height !== frame.displayHeight) {
      this.canvas.width = frame.displayWidth;
      this.canvas.height = frame.displayHeight;
    }
    this.ctx.drawImage(frame, 0, 0, this.canvas.width, this.canvas.height);
    frame.close();
  }

  /** Silently drops frames until the first key frame arrives — a delta
   *  frame with nothing decoded yet to reference is expected right after
   *  subscribing, not an error. */
  feed(bytes: Uint8Array): void {
    if (this.closed) return;
    const key = isVp8KeyFrame(bytes);
    if (!key && !this.haveKeyFrame) return;
    if (key) this.haveKeyFrame = true;
    const chunk = new EncodedVideoChunk({
      type: key ? "key" : "delta",
      timestamp: performance.now() * 1000,
      data: bytes,
    });
    try {
      this.decoder.decode(chunk);
    } catch (err) {
      console.error("VP8 decode failed", err);
    }
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    if (this.decoder.state !== "closed") this.decoder.close();
  }
}
