import {
  api,
  DaemonError,
  type Contact,
  type Conversation,
  type Device,
  type FileMetaPublic,
  type GroupDTO,
  type Message,
  type NetworkCallSummary,
  type PaymentAsset,
  type PaymentRequestView,
  type ProfileMeta,
} from "./api";
import {
  isLinkPreviewsEnabled,
  setLinkPreviewsEnabled,
  LINK_PREVIEW_SETTING_COPY,
  renderLinkPreviewCard,
} from "./link_preview";
import { ensureDaemonRunning } from "./daemon_lifecycle";
import { subscribeToCallStream, FrameKind, Vp8CanvasRenderer, type CallEvent } from "./calls";
import {
  bytesToHex,
  clearPrfUnlockConfig,
  derivePrfSecret,
  enrollDatabaseUnlockGate,
  getPrfUnlockConfig,
} from "./prf_unlock";

// Screenshot/shoulder-surfing mitigation (SPEC.md §7): blur the whole app
// whenever the window loses focus. Real, cross-platform, but not equivalent
// to OS-level capture exclusion (Windows' WDA_EXCLUDEFROMCAPTURE has no
// macOS/Linux third-party equivalent) — that would need native code per
// platform and isn't implemented here.
function installBlurOnUnfocus(root: HTMLElement) {
  window.addEventListener("blur", () => root.classList.add("bh-privacy-blur"));
  window.addEventListener("focus", () => root.classList.remove("bh-privacy-blur"));
}

function $<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) throw new Error(`missing #${id}`);
  return found as T;
}

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function showOnly(...ids: string[]) {
  for (const id of ["screen-unlock", "screen-seed", "screen-local-unlock", "screen-app"]) {
    $(id).hidden = !ids.includes(id);
  }
}

// Base64url <-> ArrayBuffer helpers for the WebAuthn JSON glue (passkey
// enroll/unlock) — the browser's `navigator.credentials` API works in
// ArrayBuffers, but the daemon (via `webauthn-rs`) speaks base64url JSON.
function base64urlToBuffer(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function bufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Base64 (standard, not url-safe) encode/decode for attachment bytes —
// chunked to avoid blowing the call stack on `String.fromCharCode(...bytes)`
// for larger files.
function bytesToBase64(bytes: Uint8Array): string {
  const CHUNK = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function formatClock(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
}

function errorMessage(err: unknown): string {
  if (err instanceof DaemonError) return `${err.message} (HTTP ${err.status})`;
  if (err instanceof Error) return err.message;
  return String(err);
}

const QUICK_REACTIONS = ["👍", "❤️", "😂", "😮", "😢"];

// ---------------- app state ----------------
let contacts: Contact[] = [];
let contactsById = new Map<string, Contact>();
let conversations: Conversation[] = [];
let activeConversationId: string | null = null;
const lastMessageCache = new Map<string, Message>();
let groups: GroupDTO[] = [];
let groupsById = new Map<string, GroupDTO>();
let currentAttachments = new Map<string, FileMetaPublic>();

let reportMode = false;
const reportSelection = new Set<string>();

let typingPollHandle: ReturnType<typeof setInterval> | null = null;
let lastTypingPingAt = 0;
const TYPING_PING_MIN_INTERVAL_MS = 3_000;

// ---------------- calls ----------------
let activeCallId: string | null = null;
let activeCallIsGroup = false;
let activeCallUnsubscribe: (() => Promise<void>) | null = null;
let remoteCallRenderer: Vp8CanvasRenderer | null = null;
let localCallRenderer: Vp8CanvasRenderer | null = null;
let cameraOn = false;
let screenShareOn = false;
const groupCallParticipants = new Set<number>();

function contactFor(conversation: Conversation): Contact | undefined {
  return conversation.contact_id ? contactsById.get(conversation.contact_id) : undefined;
}

function currentConversation(): Conversation | undefined {
  return conversations.find((c) => c.conversation_id === activeConversationId);
}

function conversationLabel(conversation: Conversation): string {
  if (conversation.kind === "self") return "Notes to self";
  if (conversation.kind === "group") {
    const group = conversation.group_id ? groupsById.get(conversation.group_id) : undefined;
    const label = group?.name || conversation.group_id || "group";
    return group?.broadcast_only ? `${label} (channel)` : label;
  }
  const contact = contactFor(conversation);
  return contact?.display_name || conversation.contact_id || "unknown contact";
}

function resetAppState() {
  stopTypingPoll();
  contacts = [];
  contactsById = new Map();
  conversations = [];
  activeConversationId = null;
  lastMessageCache.clear();
  groups = [];
  groupsById = new Map();
  currentAttachments = new Map();
  reportMode = false;
  reportSelection.clear();
  $<HTMLDivElement>("thread-empty").hidden = false;
  $<HTMLDivElement>("thread-active").hidden = true;
  // Clear rendered plaintext out of the DOM, not just the JS-side arrays
  // above — `showOnly()` only toggles `hidden` (display:none), which
  // leaves prior conversation names and decrypted message bubbles sitting
  // in the document until something re-renders over them.
  $<HTMLDivElement>("conv-list").replaceChildren();
  $<HTMLDivElement>("msgs").replaceChildren();
  for (const id of [
    "screen-security",
    "screen-store",
    "screen-search",
    "screen-add-contact",
    "screen-new-group",
    "screen-profiles",
    "screen-requests",
    "screen-import",
    "screen-call",
  ]) {
    $<HTMLDivElement>(id).hidden = true;
  }
  void hangupActiveCall();
}

// ---------------- unlock flow ----------------
/// Ensures the daemon is actually running before anything else — either
/// starting it plainly, or, if a PRF database-unlock gate is configured
/// (`prf_unlock.ts`), waiting on a passkey assertion first and starting
/// the daemon with the derived secret as `BLACKHOLE_DB_PIN`. This is the
/// real gate THREAT_MODEL.md §3.7 describes: unlike the *client-UI-only*
/// passkey/TOTP screen further down in `boot()` (which runs after the
/// daemon has already opened the database), the daemon process here
/// genuinely does not exist — and so cannot have opened anything — until
/// this resolves. Returns `false` (having already rendered its own
/// retry/unlock UI into `actions`) if the daemon isn't up yet; `boot()`
/// must stop and wait rather than proceed to `api.health()`.
async function ensureDaemonBeforeBoot(
  status: HTMLParagraphElement,
  actions: HTMLDivElement,
): Promise<boolean> {
  const gate = await getPrfUnlockConfig().catch(() => null);

  if (!gate) {
    try {
      status.textContent = "Starting daemon…";
      await ensureDaemonRunning(null);
      return true;
    } catch (err) {
      status.textContent = `Could not start the daemon: ${errorMessage(err)}`;
      const retry = el("button", "btn-outline wide", "Retry");
      retry.type = "button";
      retry.addEventListener("click", boot);
      actions.append(retry);
      return false;
    }
  }

  status.textContent = "This profile's database is locked. Unlock with your passkey to continue.";
  const unlockBtn = el("button", "btn-primary wide", "Unlock with passkey");
  unlockBtn.type = "button";
  unlockBtn.addEventListener("click", async () => {
    unlockBtn.disabled = true;
    status.textContent = "Waiting for your passkey…";
    try {
      const secret = await derivePrfSecret(gate);
      if (!secret) {
        throw new Error("Your authenticator did not return a PRF result.");
      }
      await ensureDaemonRunning(bytesToHex(secret));
      await boot();
    } catch (err) {
      status.textContent = errorMessage(err);
      unlockBtn.disabled = false;
    }
  });
  actions.append(unlockBtn);
  return false;
}

async function boot() {
  const status = $<HTMLParagraphElement>("unlock-status");
  const actions = $<HTMLDivElement>("unlock-actions");
  actions.replaceChildren();
  showOnly("screen-unlock");

  if (!(await ensureDaemonBeforeBoot(status, actions))) return;
  actions.replaceChildren();

  try {
    await api.health();
  } catch {
    status.textContent = "Daemon unreachable — is it running?";
    const retry = el("button", "btn-outline wide", "Retry");
    retry.type = "button";
    retry.addEventListener("click", boot);
    actions.append(retry);
    return;
  }

  let identity;
  try {
    identity = await api.getIdentity();
  } catch (err) {
    status.textContent = errorMessage(err);
    return;
  }

  if (!identity.initialized) {
    status.textContent = "No identity on this profile yet.";
    const create = el("button", "btn-primary", "Create identity");
    create.type = "button";
    create.addEventListener("click", () => createIdentity(status, create));
    actions.append(create);
    return;
  }

  status.textContent = `Identity found · ${identity.public_signing_key?.slice(0, 12)}…`;
  const cont = el("button", "btn-primary", "Continue");
  cont.type = "button";
  cont.addEventListener("click", () => proceedPastUnlock());
  actions.append(cont);
}

/// After the seed/identity gate, checks whether a passkey/TOTP local
/// unlock is enrolled for this profile — if so, that screen must succeed
/// before `enterApp()`; otherwise it's skipped entirely (additive/opt-in,
/// see `local_auth.rs` module doc — this does not gate the database key).
async function proceedPastUnlock() {
  let status;
  try {
    status = await api.localAuthStatus();
  } catch (err) {
    // Fail closed by default: if the check itself fails there's no way to
    // tell whether a passkey/TOTP gate is actually enrolled, so silently
    // entering the app could skip a real gate. Offer a retry plus an
    // explicit, deliberate escape hatch instead of picking for the user.
    const unlockStatus = $<HTMLParagraphElement>("unlock-status");
    const actions = $<HTMLDivElement>("unlock-actions");
    unlockStatus.textContent = `Could not check local-unlock status: ${errorMessage(err)}`;
    actions.replaceChildren();
    const retry = el("button", "btn-primary", "Retry");
    retry.type = "button";
    retry.addEventListener("click", () => proceedPastUnlock());
    const skip = el("button", "btn-outline", "Continue anyway");
    skip.type = "button";
    skip.addEventListener("click", () => enterApp());
    actions.append(retry, skip);
    return;
  }
  if (status.passkey_enrolled || status.totp_enrolled) {
    showLocalUnlockScreen(status);
  } else {
    await enterApp();
  }
}

function showLocalUnlockScreen(status: { passkey_enrolled: boolean; totp_enrolled: boolean }) {
  showOnly("screen-local-unlock");
  const error = $<HTMLParagraphElement>("local-unlock-error");
  error.hidden = true;
  const passkeyBtn = $<HTMLButtonElement>("local-unlock-passkey");
  const codeInput = $<HTMLInputElement>("local-unlock-code");
  const totpBtn = $<HTMLButtonElement>("local-unlock-totp-submit");
  passkeyBtn.hidden = !status.passkey_enrolled;
  codeInput.hidden = !status.totp_enrolled;
  totpBtn.hidden = !status.totp_enrolled;
  codeInput.value = "";

  passkeyBtn.onclick = async () => {
    error.hidden = true;
    try {
      const { ceremony_id, challenge_json } = await api.passkeyAuthStart();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const publicKey = (challenge_json as any).publicKey;
      const options = {
        publicKey: {
          ...publicKey,
          challenge: base64urlToBuffer(publicKey.challenge),
          allowCredentials: (publicKey.allowCredentials ?? []).map((c: { id: string }) => ({
            ...c,
            id: base64urlToBuffer(c.id),
          })),
        },
      } as CredentialRequestOptions;
      const assertion = (await navigator.credentials.get(options)) as PublicKeyCredential;
      const response = assertion.response as AuthenticatorAssertionResponse;
      const credentialJson = {
        id: assertion.id,
        rawId: bufferToBase64url(assertion.rawId),
        type: assertion.type,
        response: {
          clientDataJSON: bufferToBase64url(response.clientDataJSON),
          authenticatorData: bufferToBase64url(response.authenticatorData),
          signature: bufferToBase64url(response.signature),
          userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null,
        },
      };
      await api.passkeyAuthFinish(ceremony_id, credentialJson);
      await enterApp();
    } catch (err) {
      error.hidden = false;
      error.textContent = errorMessage(err);
    }
  };

  totpBtn.onclick = async () => {
    error.hidden = true;
    try {
      await api.totpVerify(codeInput.value.trim());
      await enterApp();
    } catch (err) {
      error.hidden = false;
      error.textContent = errorMessage(err);
    }
  };
}

async function createIdentity(status: HTMLParagraphElement, button: HTMLButtonElement) {
  button.disabled = true;
  status.textContent = "Generating identity keys…";
  try {
    const created = await api.createIdentity();
    showSeedScreen(created.seed_phrase);
  } catch (err) {
    status.textContent = errorMessage(err);
    button.disabled = false;
  }
}

function showSeedScreen(seedPhrase: string) {
  showOnly("screen-seed");
  $<HTMLDivElement>("seed-words").textContent = seedPhrase;
  const confirm = $<HTMLInputElement>("seed-confirm");
  const cont = $<HTMLButtonElement>("seed-continue");
  confirm.checked = false;
  cont.disabled = true;
  confirm.onchange = () => {
    cont.disabled = !confirm.checked;
  };
  cont.onclick = () => enterApp();
}

// ---------------- main app ----------------
async function enterApp() {
  showOnly("screen-app");
  await Promise.all([refreshContacts(), refreshConversations(), refreshGroups(), refreshRequestsBadge()]);
}

async function refreshContacts() {
  contacts = await api.listContacts();
  contactsById = new Map(contacts.map((c) => [c.contact_id, c]));
}

async function refreshGroups() {
  try {
    groups = await api.listGroups();
    groupsById = new Map(groups.map((g) => [g.group_id, g]));
    renderConvList();
  } catch {
    // Best-effort — conversation labels just fall back to the raw id.
  }
}

async function refreshConversations() {
  conversations = await api.listConversations();
  renderConvList();
}

async function refreshRequestsBadge() {
  const badge = $<HTMLSpanElement>("requests-badge");
  try {
    const pending = (await api.listMessageRequests()).filter((r) => r.status === "pending");
    if (pending.length > 0) {
      badge.textContent = String(pending.length);
      badge.hidden = false;
    } else {
      badge.hidden = true;
    }
  } catch {
    badge.hidden = true;
  }
}

function renderConvList() {
  const list = $<HTMLDivElement>("conv-list");
  list.replaceChildren();

  if (conversations.length === 0) {
    list.append(el("div", "conv-preview", "No conversations yet."));
    return;
  }

  // Pin "Notes to self" at the top — it's the one conversation every
  // profile always has, not something the user picked from a list.
  const ordered = [...conversations].sort((a, b) =>
    a.kind === "self" ? -1 : b.kind === "self" ? 1 : 0,
  );

  for (const conversation of ordered) {
    const item = el("div", `conv-item${conversation.kind === "self" ? " conv-item-self" : ""}`);
    if (conversation.conversation_id === activeConversationId) item.classList.add("active");
    item.append(el("i", "ring-avatar"));

    const meta = el("div", "conv-meta");
    meta.append(el("div", "conv-name", conversationLabel(conversation)));
    const cached = lastMessageCache.get(conversation.conversation_id);
    meta.append(el("div", "conv-preview", cached?.body ?? "Tap to view messages"));
    item.append(meta);

    item.addEventListener("click", () => openConversation(conversation.conversation_id));
    list.append(item);
  }
}

function stopTypingPoll() {
  if (typingPollHandle !== null) {
    clearInterval(typingPollHandle);
    typingPollHandle = null;
  }
  $<HTMLDivElement>("typing-status").textContent = "";
}

function startTypingPoll(conversationId: string) {
  stopTypingPoll();
  const statusEl = $<HTMLDivElement>("typing-status");
  const poll = async () => {
    try {
      const status = await api.getTypingStatus(conversationId);
      if (status.typing && status.contact_id) {
        const contact = contactsById.get(status.contact_id);
        statusEl.textContent = `${contact?.display_name || "Someone"} is typing…`;
      } else {
        statusEl.textContent = "";
      }
    } catch {
      // Polling failure isn't worth surfacing — just leave the last state.
    }
  };
  poll();
  typingPollHandle = setInterval(poll, 2_000);
}

async function openConversation(conversationId: string) {
  activeConversationId = conversationId;
  reportMode = false;
  reportSelection.clear();
  $<HTMLDivElement>("report-bar").hidden = true;
  $<HTMLDivElement>("export-panel").hidden = true;
  $<HTMLDivElement>("payment-panel").hidden = true;
  $<HTMLDivElement>("members-panel").hidden = true;
  renderConvList();

  const conversation = conversations.find((c) => c.conversation_id === conversationId);
  if (!conversation) return;
  const contact = contactFor(conversation);
  const isGroup = conversation.kind === "group";

  // Typing indicators are direct-conversation-only (see
  // `bh-api::presence::send_typing_ping`) — no polling for groups/self.
  if (conversation.kind === "direct") {
    startTypingPoll(conversationId);
  } else {
    stopTypingPoll();
  }

  $<HTMLDivElement>("thread-empty").hidden = true;
  const active = $<HTMLDivElement>("thread-active");
  active.hidden = false;

  $<HTMLDivElement>("thread-who").textContent = conversationLabel(conversation);
  $<HTMLDivElement>("thread-sub").textContent = conversation.disappearing_timer_secs
    ? `disappearing · ${conversation.disappearing_timer_secs}s`
    : "";

  renderVerifyChip(contact ?? null);
  renderBlockToggle(contact ?? null);
  renderTimerSelect(conversation);
  $<HTMLButtonElement>("report-contact").disabled = !contact;
  $<HTMLButtonElement>("manage-members").hidden = !isGroup;
  $<HTMLButtonElement>("verify-group-crypto").hidden = !isGroup;
  $<HTMLButtonElement>("call-audio").hidden = conversation.kind !== "direct";
  $<HTMLButtonElement>("call-video").hidden = conversation.kind !== "direct";
  $<HTMLButtonElement>("call-group").hidden = !isGroup;

  const msgs = $<HTMLDivElement>("msgs");
  msgs.replaceChildren(el("div", "msg-meta", "Loading…"));
  currentAttachments = new Map();
  try {
    const [messages, attachments] = await Promise.all([
      api.listMessages(conversationId),
      api.listAttachments(conversationId).catch(() => []),
    ]);
    currentAttachments = new Map(attachments.filter((f) => f.message_id).map((f) => [f.message_id as string, f]));
    renderMessages(messages);
    if (messages.length > 0) {
      lastMessageCache.set(conversationId, messages[messages.length - 1]);
      renderConvList();
    }
  } catch (err) {
    msgs.replaceChildren(el("div", "msg-meta", errorMessage(err)));
  }
}

// ---------------- calls ----------------
// 1:1 calls (`call-audio`/`call-video`) now pass the open conversation's
// real `contact_id` to `POST /calls`, which routes the offer over the real
// X3DH/Double-Ratchet mailbox the same way `Direct` chat messages do
// (`bh-api::calls::start_call`/`handle_incoming_call_signal`) — a real
// WebRTC connection, real media capture/encode, and real SFrame end-to-end
// encryption, genuinely between two separate daemons/devices when both are
// reachable on the network. There is still no unprompted "incoming call"
// UI on the callee side — the daemon auto-answers server-side the moment
// an `Offer` arrives, so a real callee's own client only becomes aware of
// the call once its media starts flowing, not before. Falls back to the
// old same-daemon demo path (this client plays both caller and callee
// roles) whenever the open conversation has no resolved `contact_id` (e.g.
// "Notes to self") — same fallback shape as `conversations::send_message`'s
// `Direct` arm already uses when no live network is attached. Group calls
// (`call-group`) are unchanged and still same-daemon-only: `bh-api::calls`
// deliberately doesn't route `GroupOffer`/`GroupAnswer` over the network
// yet (see that module's own doc comment).

function setCallStatus(text: string) {
  $<HTMLParagraphElement>("call-status").textContent = text;
}

function updateCallControls() {
  $<HTMLButtonElement>("call-toggle-camera").hidden = activeCallIsGroup;
  $<HTMLButtonElement>("call-toggle-screen").hidden = activeCallIsGroup;
  $<HTMLButtonElement>("call-toggle-camera").textContent = cameraOn ? "Stop camera" : "Start camera";
  $<HTMLButtonElement>("call-toggle-screen").textContent = screenShareOn ? "Stop sharing" : "Share screen";
  $<HTMLDivElement>("call-videos").hidden = activeCallIsGroup;
  $<HTMLDivElement>("call-participants").hidden = !activeCallIsGroup;
}

function renderGroupCallParticipants() {
  const container = $<HTMLDivElement>("call-participants");
  container.replaceChildren();
  for (const tag of Array.from(groupCallParticipants).sort((a, b) => a - b)) {
    container.append(el("div", "call-participant-tile", tag === 0 ? "You" : `Participant ${tag}`));
  }
}

function handleCallEvent(event: CallEvent) {
  switch (event.type) {
    case "connected":
      setCallStatus("Connected");
      break;
    case "participant_joined":
      groupCallParticipants.add(event.tag);
      renderGroupCallParticipants();
      break;
    case "participant_left":
      groupCallParticipants.delete(event.tag);
      renderGroupCallParticipants();
      break;
    case "hangup":
      setCallStatus("Call ended");
      void endCallUi();
      break;
  }
}

function openCallOverlay(title: string, isGroup: boolean) {
  activeCallIsGroup = isGroup;
  cameraOn = false;
  screenShareOn = false;
  groupCallParticipants.clear();
  $<HTMLSpanElement>("call-title").textContent = title;
  setCallStatus("Connecting…");
  updateCallControls();
  renderGroupCallParticipants();
  $<HTMLDivElement>("screen-call").hidden = false;
}

async function endCallUi() {
  if (activeCallUnsubscribe) {
    await activeCallUnsubscribe().catch(() => {});
    activeCallUnsubscribe = null;
  }
  remoteCallRenderer?.close();
  localCallRenderer?.close();
  remoteCallRenderer = null;
  localCallRenderer = null;
  activeCallId = null;
  activeCallIsGroup = false;
  cameraOn = false;
  screenShareOn = false;
  groupCallParticipants.clear();
  $<HTMLDivElement>("screen-call").hidden = true;
}

async function hangupActiveCall() {
  const callId = activeCallId;
  if (!callId) {
    $<HTMLDivElement>("screen-call").hidden = true;
    return;
  }
  try {
    if (activeCallIsGroup) await api.hangupGroupCall(callId);
    else await api.hangupCall(callId);
  } catch {
    // Best-effort — still tear down the local UI/subscription below even
    // if the daemon-side hangup call failed (e.g. already ended).
  }
  await endCallUi();
}

async function attachCallStream(callId: string) {
  activeCallId = callId;
  remoteCallRenderer = new Vp8CanvasRenderer($<HTMLCanvasElement>("call-remote-video"));
  localCallRenderer = new Vp8CanvasRenderer($<HTMLCanvasElement>("call-local-video"));
  activeCallUnsubscribe = await subscribeToCallStream(callId, {
    onEvent: handleCallEvent,
    onFrame: (frame) => {
      if (frame.kind === FrameKind.RemoteVideo || frame.kind === FrameKind.RemoteScreen) {
        remoteCallRenderer?.feed(frame.bytes);
      } else {
        localCallRenderer?.feed(frame.bytes);
      }
    },
  });
}

// Minimal visibility for a real-network call this client didn't place
// itself (`GET /calls/network`, `bh-api::calls::list_network_calls`) —
// there's no "ringing, not yet answered" state to notify on, since the
// daemon auto-accepts an incoming `Offer` immediately, so this only ever
// surfaces calls that are already connected (a banner + a way to attach to
// the stream), not a full pre-accept ringing UI.
const seenNetworkCallIds = new Set<string>();

function showIncomingCallBanner(summary: NetworkCallSummary) {
  const name = contactsById.get(summary.contact_id)?.display_name || "Someone";
  const banner = $<HTMLDivElement>("incoming-call-banner");
  $<HTMLSpanElement>("incoming-call-banner-text").textContent = `Call with ${name}`;
  banner.hidden = false;

  const joinBtn = $<HTMLButtonElement>("incoming-call-banner-join");
  const dismissBtn = $<HTMLButtonElement>("incoming-call-banner-dismiss");
  const cleanup = () => {
    banner.hidden = true;
    joinBtn.removeEventListener("click", onJoin);
    dismissBtn.removeEventListener("click", onDismiss);
  };
  const onJoin = () => {
    cleanup();
    openCallOverlay(`Call with ${name}`, false);
    void attachCallStream(summary.call_id);
  };
  const onDismiss = () => cleanup();
  joinBtn.addEventListener("click", onJoin);
  dismissBtn.addEventListener("click", onDismiss);
}

async function pollIncomingNetworkCalls() {
  let calls: NetworkCallSummary[];
  try {
    calls = await api.listNetworkCalls();
  } catch {
    return; // best-effort — daemon not reachable yet, or a transient error
  }
  for (const summary of calls) {
    if (summary.call_id === activeCallId || seenNetworkCallIds.has(summary.call_id)) continue;
    seenNetworkCallIds.add(summary.call_id);
    showIncomingCallBanner(summary);
  }
}

async function startCall(video: boolean) {
  const callId = crypto.randomUUID();
  // This client placed the call itself — never show it its own incoming-
  // call banner once `pollIncomingNetworkCalls` sees it in the same list.
  seenNetworkCallIds.add(callId);
  const contactId = currentConversation()?.contact_id ?? undefined;
  openCallOverlay(video ? "Video call" : "Call", false);
  try {
    const offer = await api.startCall(callId, video, contactId);
    if (contactId) {
      // Real network call: `bh-api::calls::start_call` already pushed the
      // offer through the contact's mailbox, and their daemon auto-answers
      // on its own — nothing left to do here but attach to this call's
      // stream and wait for a "connected" event (`handleCallEvent`).
      await attachCallStream(callId);
    } else {
      // No contact in scope for the open conversation (e.g. "Notes to
      // self", or a conversation with no resolved contact) — fall back to
      // the same-daemon demo path this UI has always used.
      const answer = await api.acceptCall(offer.signal);
      await api.completeCall(callId, answer.signal);
      await attachCallStream(callId);
    }
  } catch (err) {
    setCallStatus(`Failed to start call: ${errorMessage(err)}`);
  }
}

async function startTestGroupCall() {
  const callId = crypto.randomUUID();
  openCallOverlay("Group call (local test)", true);
  try {
    const started = await api.startGroupCall(callId, false, 2);
    groupCallParticipants.add(started.local_tag);
    for (const tag of started.participant_tags) groupCallParticipants.add(tag);
    renderGroupCallParticipants();
    await attachCallStream(callId);
  } catch (err) {
    setCallStatus(`Failed to start group call: ${errorMessage(err)}`);
  }
}

$<HTMLButtonElement>("call-audio").addEventListener("click", () => void startCall(false));
$<HTMLButtonElement>("call-video").addEventListener("click", () => void startCall(true));
$<HTMLButtonElement>("call-group").addEventListener("click", () => void startTestGroupCall());
$<HTMLButtonElement>("close-call").addEventListener("click", () => void hangupActiveCall());
$<HTMLButtonElement>("call-hangup").addEventListener("click", () => void hangupActiveCall());
$<HTMLButtonElement>("call-toggle-camera").addEventListener("click", async () => {
  if (!activeCallId) return;
  try {
    if (cameraOn) {
      await api.stopCamera(activeCallId);
      cameraOn = false;
    } else {
      await api.startCamera(activeCallId);
      cameraOn = true;
    }
    updateCallControls();
  } catch (err) {
    setCallStatus(`Camera error: ${errorMessage(err)}`);
  }
});
$<HTMLButtonElement>("call-toggle-screen").addEventListener("click", async () => {
  if (!activeCallId) return;
  try {
    if (screenShareOn) {
      await api.stopScreenShare(activeCallId);
      screenShareOn = false;
    } else {
      await api.startScreenShare(activeCallId);
      screenShareOn = true;
    }
    updateCallControls();
  } catch (err) {
    setCallStatus(`Screen share error: ${errorMessage(err)}`);
  }
});

function renderMessages(messages: Message[]) {
  const msgs = $<HTMLDivElement>("msgs");
  msgs.replaceChildren();
  for (const message of messages) {
    msgs.append(renderMessage(message));
  }
  msgs.scrollTop = msgs.scrollHeight;
}

function renderMessage(message: Message): HTMLDivElement {
  const outgoing = message.sender_contact_id === null;
  const row = el("div", `msg-row ${outgoing ? "out" : "in"}`);
  if (reportMode) row.classList.add("selectable");
  row.dataset.messageId = message.message_id;
  // Lets `pruneExpiredMessages` find and remove this bubble once its
  // disappearing-message timer fires, even while the conversation stays
  // open and nothing else re-renders it (see that function's doc).
  if (message.expires_at !== null) row.dataset.expiresAt = String(message.expires_at);

  if (reportMode) {
    const checkbox = el("input") as HTMLInputElement;
    checkbox.type = "checkbox";
    checkbox.checked = reportSelection.has(message.message_id);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) reportSelection.add(message.message_id);
      else reportSelection.delete(message.message_id);
      $<HTMLSpanElement>("report-count").textContent = String(reportSelection.size);
    });
    row.append(checkbox);
  }

  const attachment = currentAttachments.get(message.message_id);
  const isVoiceMessage = attachment?.attachment_kind === "voice";

  const stack = el("div");
  const bubble = el("div", "bubble", message.body ?? (isVoiceMessage ? "" : "(empty message)"));
  stack.append(bubble);
  if (isVoiceMessage) {
    bubble.append(renderVoicePlayer(attachment));
  } else if (message.body === null) {
    loadMessageSticker(message.message_id, bubble);
  }
  if (message.body !== null) {
    const previewSlot = el("div");
    stack.append(previewSlot);
    renderLinkPreviewCard(message.body).then((card) => {
      if (card) previewSlot.append(card);
    });
  }

  if (attachment && !isVoiceMessage) {
    stack.append(
      renderAttachmentChip(attachment, outgoing, () => {
        currentAttachments.delete(message.message_id);
        row.querySelector(".attachment-chip-wrap")?.remove();
      }),
    );
  }

  const paymentSlot = el("div");
  stack.append(paymentSlot);
  loadPaymentRequest(message.message_id, paymentSlot);

  const meta = el("div", "msg-meta");
  meta.append(document.createTextNode(formatClock(message.sent_at)));
  if (message.edited_at !== null) {
    const editedLabel = el("span", "edited-label", "edited");
    editedLabel.title = "Click to view edit history";
    editedLabel.addEventListener("click", () => showEditHistory(message.message_id));
    meta.append(editedLabel);
  }
  stack.append(meta);

  // Only the local user's own text messages (not stickers, which have
  // `body: null`) can be edited — mirrors the server-side check in
  // `bh-api::conversations::edit_message`.
  if (outgoing && message.body !== null) {
    const editBtn = el("button", "edit-msg-btn", "edit");
    editBtn.type = "button";
    editBtn.addEventListener("click", () => startEditingMessage(message, bubble));
    meta.append(editBtn);
  }

  const reactions = el("div", "msg-reactions");
  stack.append(reactions);
  loadReactions(message.message_id, reactions);

  if (outgoing) {
    const receiptBadge = el("span", "mono");
    meta.append(receiptBadge);
    loadReceiptBadge(message.message_id, receiptBadge);
  }

  row.append(stack);
  return row;
}

function startEditingMessage(message: Message, bubble: HTMLDivElement) {
  if (!activeConversationId) return;
  const originalText = bubble.textContent ?? "";
  bubble.replaceChildren();
  const input = el("input", "field") as HTMLInputElement;
  input.value = message.body ?? "";
  const save = el("button", "chip-btn", "Save");
  save.type = "button";
  const cancel = el("button", "chip-btn", "Cancel");
  cancel.type = "button";
  const row = el("div", "edit-msg-row");
  row.append(input, save, cancel);
  bubble.append(row);
  input.focus();

  const restore = (text: string) => {
    bubble.replaceChildren();
    bubble.textContent = text;
  };
  cancel.addEventListener("click", () => restore(originalText));
  save.addEventListener("click", async () => {
    const body = input.value.trim();
    if (!body || !activeConversationId) return;
    save.disabled = true;
    try {
      const { message: updated } = await api.editMessage(activeConversationId, message.message_id, body);
      message.body = updated.body;
      message.edited_at = updated.edited_at;
      restore(updated.body ?? "");
      openConversation(activeConversationId);
    } catch (err) {
      window.alert(errorMessage(err));
      restore(originalText);
    }
  });
}

async function showEditHistory(messageId: string) {
  if (!activeConversationId) return;
  try {
    const { edits } = await api.listMessageEdits(activeConversationId, messageId);
    const text = edits.length
      ? edits.map((e) => `${formatClock(e.edited_at)}: ${e.body ?? "(empty)"}`).join("\n")
      : "No prior versions.";
    window.alert(`Edit history:\n\n${text}`);
  } catch (err) {
    window.alert(errorMessage(err));
  }
}

/// Removes any rendered message bubble whose disappearing-message timer
/// has passed, even though nothing else caused the thread to re-render.
/// Without this, a message left visible in an *open* conversation stays
/// on screen past its intended expiry until the user navigates away and
/// back (which re-fetches from the daemon, where the sweeper has already
/// purged it) — the plaintext just sits there in the meantime.
function pruneExpiredMessages() {
  const nowSeconds = Date.now() / 1000;
  for (const row of $<HTMLDivElement>("msgs").querySelectorAll<HTMLDivElement>("[data-expires-at]")) {
    if (Number(row.dataset.expiresAt) <= nowSeconds) row.remove();
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDuration(seconds: number | null): string {
  if (seconds === null) return "";
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}:${String(s).padStart(2, "0")}`;
}

/// A voice message's inline player. Audio bytes are fetched lazily on
/// first play, not eagerly for every message in the list — same "don't
/// pull ciphertext off disk until asked" spirit as `renderAttachmentChip`.
function renderVoicePlayer(file: FileMetaPublic): HTMLDivElement {
  const wrap = el("div", "voice-player");
  const playBtn = el("button", "voice-play-btn", "▶") as HTMLButtonElement;
  playBtn.type = "button";
  const durationLabel = el("span", "voice-duration mono", formatDuration(file.duration_secs));
  wrap.append(playBtn, durationLabel);

  let audioEl: HTMLAudioElement | null = null;
  playBtn.addEventListener("click", async () => {
    if (audioEl) {
      if (audioEl.paused) audioEl.play();
      else audioEl.pause();
      return;
    }
    playBtn.disabled = true;
    try {
      const downloaded = await api.downloadAttachment(file.content_hash);
      const byteChars = atob(downloaded.data_base64);
      const bytes = new Uint8Array(byteChars.length);
      for (let i = 0; i < byteChars.length; i++) bytes[i] = byteChars.charCodeAt(i);
      const blob = new Blob([bytes], { type: downloaded.mime_type || "audio/webm" });
      audioEl = new Audio(URL.createObjectURL(blob));
      audioEl.addEventListener("play", () => {
        playBtn.textContent = "⏸";
      });
      audioEl.addEventListener("pause", () => {
        playBtn.textContent = "▶";
      });
      audioEl.addEventListener("ended", () => {
        playBtn.textContent = "▶";
      });
      await audioEl.play();
    } catch (err) {
      window.alert(errorMessage(err));
    } finally {
      playBtn.disabled = false;
    }
  });

  return wrap;
}

function renderAttachmentChip(
  file: FileMetaPublic,
  outgoing: boolean,
  onDeleted?: () => void,
): HTMLDivElement {
  const wrap = el("div", "attachment-chip-wrap");
  const chip = el("button", "attachment-chip");
  chip.type = "button";
  chip.append(el("span", "attachment-icon", "📎"));
  chip.append(document.createTextNode(file.file_name ?? "file"));
  chip.append(el("span", "attachment-size", formatBytes(file.size_bytes)));
  chip.addEventListener("click", async () => {
    chip.disabled = true;
    try {
      const downloaded = await api.downloadAttachment(file.content_hash);
      const bytes = base64ToBytes(downloaded.data_base64);
      const blob = new Blob([bytes], { type: downloaded.mime_type ?? "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const link = el("a") as HTMLAnchorElement;
      link.href = url;
      link.download = downloaded.file_name ?? "download";
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      window.alert(errorMessage(err));
    } finally {
      chip.disabled = false;
    }
  });
  wrap.append(chip);

  // Only the sender can delete their own upload — the recipient's copy of
  // an incoming attachment stays theirs to keep.
  if (outgoing) {
    const del = el("button", "attachment-delete", "✕");
    del.type = "button";
    del.title = "Delete attachment";
    del.addEventListener("click", async (event) => {
      event.stopPropagation();
      if (!window.confirm("Delete this attachment? This cannot be undone.")) return;
      del.disabled = true;
      try {
        await api.deleteAttachment(file.content_hash);
        onDeleted?.();
      } catch (err) {
        window.alert(errorMessage(err));
        del.disabled = false;
      }
    });
    wrap.append(del);
  }
  return wrap;
}

async function loadReactions(messageId: string, container: HTMLDivElement) {
  try {
    const reactions = await api.listReactions(messageId);
    renderReactionChips(messageId, container, reactions);
  } catch {
    // Best-effort — a message still renders fine without its reactions.
  }
}

function renderReactionChips(
  messageId: string,
  container: HTMLDivElement,
  reactions: Awaited<ReturnType<typeof api.listReactions>>,
) {
  container.replaceChildren();
  const counts = new Map<string, { count: number; mine: boolean }>();
  for (const reaction of reactions) {
    const entry = counts.get(reaction.emoji) ?? { count: 0, mine: false };
    entry.count += 1;
    if (reaction.contact_id === null) entry.mine = true;
    counts.set(reaction.emoji, entry);
  }
  for (const [emoji, { count, mine }] of counts) {
    const chip = el("button", `reaction-chip${mine ? " mine" : ""}`, `${emoji} ${count}`);
    chip.type = "button";
    chip.addEventListener("click", async () => {
      try {
        if (mine) await api.removeReaction(messageId, emoji);
        else await api.addReaction(messageId, emoji);
        loadReactions(messageId, container);
      } catch (err) {
        window.alert(errorMessage(err));
      }
    });
    container.append(chip);
  }

  const trigger = el("button", "react-trigger", "react");
  trigger.type = "button";
  trigger.addEventListener("click", () => {
    const existingPicker = container.querySelector(".react-picker");
    if (existingPicker) {
      existingPicker.remove();
      return;
    }
    const picker = el("div", "react-picker");
    for (const emoji of QUICK_REACTIONS) {
      const btn = el("button", undefined, emoji);
      btn.type = "button";
      btn.addEventListener("click", async () => {
        try {
          await api.addReaction(messageId, emoji);
          loadReactions(messageId, container);
        } catch (err) {
          window.alert(errorMessage(err));
        }
      });
      picker.append(btn);
    }
    container.append(picker);
  });
  container.append(trigger);
}

async function loadReceiptBadge(messageId: string, badge: HTMLSpanElement) {
  try {
    const receipts = await api.listReceipts(messageId);
    if (receipts.length === 0) return;
    const read = receipts.some((r) => r.status === "read");
    badge.textContent = `· ${read ? "read" : "delivered"}`;
  } catch {
    // Best-effort.
  }
}

/// A message with `body: null` might be a sticker, not just an empty
/// message — check lazily, same pattern as `loadPaymentRequest`, since the
/// message list gives no other signal either way.
async function loadMessageSticker(messageId: string, bubble: HTMLDivElement) {
  try {
    const sticker = await api.getMessageSticker(messageId);
    bubble.classList.add("bubble-sticker");
    bubble.textContent = "";
    bubble.append(el("span", "sticker-glyph", "◆"), document.createTextNode(sticker.sticker_id));
  } catch {
    // 404 for an ordinary empty message — leave the placeholder text.
  }
}

async function loadPaymentRequest(messageId: string, container: HTMLDivElement) {
  try {
    const paymentRequest = await api.getPaymentRequest(messageId);
    renderPaymentBlock(messageId, container, paymentRequest);
  } catch {
    // 404 for an ordinary message — nothing to render, and any other
    // failure just means the message renders without its payment block.
  }
}

function renderPaymentBlock(
  messageId: string,
  container: HTMLDivElement,
  paymentRequest: PaymentRequestView,
) {
  container.replaceChildren();
  const block = el("div", "payment-block");

  const head = el("div", "payment-head");
  head.append(el("span", "payment-asset", paymentRequest.asset));
  head.append(el("span", "payment-privacy", paymentRequest.privacy_label));
  block.append(head);

  if (paymentRequest.amount) {
    block.append(el("div", "payment-amount", paymentRequest.amount));
  }

  const addressRow = el("div", "payment-address");
  addressRow.textContent = paymentRequest.address;
  block.append(addressRow);

  const qr = el("div", "payment-qr");
  qr.innerHTML = paymentRequest.qr_svg;
  block.append(qr);

  const actions = el("div", "payment-actions");
  const openLink = el("a", "chip-btn", "Open in wallet") as HTMLAnchorElement;
  openLink.href = `${paymentRequest.asset === "XMR" ? "monero" : paymentRequest.asset === "BTC" ? "bitcoin" : "ethereum"}:${paymentRequest.address}`;
  actions.append(openLink);

  const copyBtn = el("button", "chip-btn", "Copy address");
  copyBtn.type = "button";
  copyBtn.addEventListener("click", async () => {
    await navigator.clipboard.writeText(paymentRequest.address);
    copyBtn.textContent = "Copied";
  });
  actions.append(copyBtn);

  // "Mark as paid" is the one action here with irreversible real-world
  // consequences (crypto sent to a wrong/swapped address can't be pulled
  // back), so it doesn't fire the API call directly — it swaps in an
  // inline confirmation step anchored to this message's own payment block
  // (THREAT_MODEL.md §3.11/§4 item 13). Undoing a mark stays a single
  // click, since undo has no fund-loss risk.
  const paidSlot = el("div", "payment-paid-slot");

  function renderPaidButton() {
    paidSlot.replaceChildren();
    const paidBtn = el(
      "button",
      `chip-btn${paymentRequest.paid_at ? " paid" : ""}`,
      paymentRequest.paid_at ? "Paid ✓ (undo)" : "Mark as paid",
    );
    paidBtn.type = "button";
    paidBtn.addEventListener("click", async () => {
      if (paymentRequest.paid_at) {
        try {
          await api.unmarkPaymentRequestPaid(messageId);
          const refreshed = await api.getPaymentRequest(messageId);
          renderPaymentBlock(messageId, container, refreshed);
        } catch (err) {
          window.alert(errorMessage(err));
        }
        return;
      }
      renderConfirm();
    });
    paidSlot.append(paidBtn);
  }

  function renderConfirm() {
    paidSlot.replaceChildren();
    const confirm = el("div", "payment-confirm");

    confirm.append(
      el(
        "div",
        "payment-confirm-label",
        "Before marking this paid, confirm the address below is really the one your contact gave you out of band (in person, on a call, over a separately-verified channel):",
      ),
    );

    const confirmAddress = el("div", "payment-address payment-confirm-address");
    confirmAddress.textContent = paymentRequest.address;
    confirm.append(confirmAddress);

    const checkboxLabel = el("label", "payment-confirm-check");
    const checkbox = el("input", "payment-confirm-checkbox") as HTMLInputElement;
    checkbox.type = "checkbox";
    checkboxLabel.append(checkbox);
    checkboxLabel.append(
      el(
        "span",
        undefined,
        "This address matches what my contact told me out of band",
      ),
    );
    confirm.append(checkboxLabel);

    const confirmActions = el("div", "payment-confirm-actions");
    const confirmBtn = el("button", "chip-btn payment-confirm-btn", "Confirm paid");
    confirmBtn.type = "button";
    confirmBtn.disabled = true;
    checkbox.addEventListener("change", () => {
      confirmBtn.disabled = !checkbox.checked;
    });
    confirmBtn.addEventListener("click", async () => {
      try {
        await api.markPaymentRequestPaid(messageId);
        const refreshed = await api.getPaymentRequest(messageId);
        renderPaymentBlock(messageId, container, refreshed);
      } catch (err) {
        window.alert(errorMessage(err));
      }
    });
    confirmActions.append(confirmBtn);

    const cancelBtn = el("button", "chip-btn", "Cancel");
    cancelBtn.type = "button";
    cancelBtn.addEventListener("click", () => {
      renderPaidButton();
    });
    confirmActions.append(cancelBtn);

    confirm.append(confirmActions);
    paidSlot.append(confirm);
  }

  renderPaidButton();
  actions.append(paidSlot);
  block.append(actions);

  container.append(block);
}

function renderVerifyChip(contact: Contact | null) {
  const chip = $<HTMLSpanElement>("thread-verify");
  chip.replaceChildren();
  if (!contact) {
    chip.hidden = true;
    return;
  }
  chip.hidden = false;
  chip.className = `verify-chip ${contact.verified ? "verified" : "unverified"}`;
  chip.textContent = contact.verified ? "verified" : "unverified";
  chip.onclick = contact.verified ? null : () => verifyContact(contact);
}

async function verifyContact(contact: Contact) {
  try {
    const safetyNumber = await api.getSafetyNumber(contact.contact_id);
    const confirmed = window.confirm(
      `Safety number for ${contact.display_name ?? contact.contact_id}:\n\n${safetyNumber.grouped}\n\n` +
        "Compare this with your contact over a separate channel. Mark as verified only if it matches exactly.",
    );
    if (!confirmed) return;
    await api.setVerified(contact.contact_id, true);
    contact.verified = true;
    renderVerifyChip(contact);
  } catch (err) {
    window.alert(errorMessage(err));
  }
}

function renderBlockToggle(contact: Contact | null) {
  const button = $<HTMLButtonElement>("toggle-block");
  if (!contact) {
    button.hidden = true;
    return;
  }
  button.hidden = false;
  button.textContent = contact.blocked ? "Unblock" : "Block";
  button.classList.toggle("danger", !contact.blocked);
  button.onclick = async () => {
    try {
      if (contact.blocked) await api.unblockContact(contact.contact_id);
      else await api.blockContact(contact.contact_id);
      contact.blocked = !contact.blocked;
      renderBlockToggle(contact);
    } catch (err) {
      window.alert(errorMessage(err));
    }
  };
}

function renderTimerSelect(conversation: Conversation) {
  const select = $<HTMLSelectElement>("timer-select");
  select.value = conversation.disappearing_timer_secs
    ? String(conversation.disappearing_timer_secs)
    : "";
  select.onchange = async () => {
    const secs = select.value ? Number(select.value) : null;
    try {
      await api.setDisappearingTimer(conversation.conversation_id, secs);
      conversation.disappearing_timer_secs = secs;
      $<HTMLDivElement>("thread-sub").textContent = secs ? `disappearing · ${secs}s` : "";
    } catch (err) {
      window.alert(errorMessage(err));
    }
  };
}

$<HTMLInputElement>("composer-field").addEventListener("input", async () => {
  if (!activeConversationId) return;
  if (!$<HTMLInputElement>("typing-indicator-toggle").checked) return;
  const now = Date.now();
  if (now - lastTypingPingAt < TYPING_PING_MIN_INTERVAL_MS) return;
  lastTypingPingAt = now;
  try {
    await api.sendTypingPing(activeConversationId);
  } catch {
    // A missed typing ping isn't worth surfacing to the user.
  }
});

$<HTMLFormElement>("composer").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!activeConversationId) return;
  const field = $<HTMLInputElement>("composer-field");
  const body = field.value.trim();
  if (!body) return;

  field.value = "";
  try {
    const { message } = await api.sendMessage(activeConversationId, body);
    $<HTMLDivElement>("msgs").append(renderMessage(message));
    $<HTMLDivElement>("msgs").scrollTop = $<HTMLDivElement>("msgs").scrollHeight;
    lastMessageCache.set(activeConversationId, message);
    renderConvList();
  } catch (err) {
    window.alert(errorMessage(err));
    field.value = body;
  }
});

// ---------------- attachments ----------------
$<HTMLButtonElement>("attach-file").addEventListener("click", () => {
  $<HTMLInputElement>("attachment-input").click();
});

$<HTMLInputElement>("attachment-input").addEventListener("change", async () => {
  const input = $<HTMLInputElement>("attachment-input");
  const file = input.files?.[0];
  if (!file || !activeConversationId) return;
  const conversationId = activeConversationId;
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const { message, file: uploaded } = await api.uploadAttachment(conversationId, {
      file_name: file.name,
      mime_type: file.type || null,
      data_base64: bytesToBase64(bytes),
    });
    currentAttachments.set(message.message_id, uploaded);
    $<HTMLDivElement>("msgs").append(renderMessage(message));
    $<HTMLDivElement>("msgs").scrollTop = $<HTMLDivElement>("msgs").scrollHeight;
    lastMessageCache.set(conversationId, message);
    renderConvList();
  } catch (err) {
    window.alert(errorMessage(err));
  } finally {
    input.value = "";
  }
});

// ---------------- voice messages ----------------
let activeRecorder: MediaRecorder | null = null;

$<HTMLButtonElement>("record-voice").addEventListener("click", async () => {
  const button = $<HTMLButtonElement>("record-voice");
  if (activeRecorder) {
    activeRecorder.stop();
    return;
  }
  if (!activeConversationId) return;
  const conversationId = activeConversationId;

  let stream: MediaStream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  } catch (err) {
    window.alert(errorMessage(err));
    return;
  }

  const chunks: Blob[] = [];
  const recorder = new MediaRecorder(stream);
  const startedAt = Date.now();
  recorder.addEventListener("dataavailable", (event) => {
    if (event.data.size > 0) chunks.push(event.data);
  });
  recorder.addEventListener("stop", async () => {
    stream.getTracks().forEach((track) => track.stop());
    activeRecorder = null;
    button.classList.remove("recording");
    button.textContent = "🎙";

    const durationSecs = Math.max(1, Math.round((Date.now() - startedAt) / 1000));
    const blob = new Blob(chunks, { type: recorder.mimeType || "audio/webm" });
    const bytes = new Uint8Array(await blob.arrayBuffer());
    if (bytes.length === 0) return;
    try {
      const { message, file: uploaded } = await api.uploadAttachment(conversationId, {
        mime_type: blob.type || null,
        data_base64: bytesToBase64(bytes),
        duration_secs: durationSecs,
      });
      currentAttachments.set(message.message_id, uploaded);
      $<HTMLDivElement>("msgs").append(renderMessage(message));
      $<HTMLDivElement>("msgs").scrollTop = $<HTMLDivElement>("msgs").scrollHeight;
      lastMessageCache.set(conversationId, message);
      renderConvList();
    } catch (err) {
      window.alert(errorMessage(err));
    }
  });

  activeRecorder = recorder;
  button.classList.add("recording");
  button.textContent = "⏹";
  recorder.start();
});

// ---------------- report flow ----------------
$<HTMLButtonElement>("report-contact").addEventListener("click", async () => {
  if (!activeConversationId) return;
  reportMode = true;
  reportSelection.clear();
  $<HTMLSpanElement>("report-count").textContent = "0";
  $<HTMLDivElement>("report-bar").hidden = false;
  const messages = await api.listMessages(activeConversationId);
  renderMessages(messages);
});

$<HTMLButtonElement>("report-cancel").addEventListener("click", async () => {
  reportMode = false;
  reportSelection.clear();
  $<HTMLDivElement>("report-bar").hidden = true;
  if (activeConversationId) renderMessages(await api.listMessages(activeConversationId));
});

$<HTMLButtonElement>("report-submit").addEventListener("click", async (event) => {
  const button = event.currentTarget as HTMLButtonElement;
  if (button.disabled) return;
  const conversation = currentConversation();
  const contact = conversation ? contactFor(conversation) : undefined;
  const reason = $<HTMLInputElement>("report-reason").value.trim();
  if (!contact) return;
  if (reportSelection.size === 0 || !reason) {
    window.alert("Pick at least one message and write a reason.");
    return;
  }
  button.disabled = true;
  try {
    const bundle = await api.createReport({
      contact_id: contact.contact_id,
      reason,
      message_ids: [...reportSelection],
    });
    window.alert(
      `Report compiled: ${bundle.messages.length} message(s) against ${bundle.contact_id}.\n\n` +
        "There is no moderation-review infrastructure to send this to yet — it's kept local.",
    );
    $<HTMLInputElement>("report-reason").value = "";
    reportMode = false;
    reportSelection.clear();
    $<HTMLDivElement>("report-bar").hidden = true;
    if (activeConversationId) renderMessages(await api.listMessages(activeConversationId));
  } catch (err) {
    window.alert(errorMessage(err));
  } finally {
    button.disabled = false;
  }
});

// ---------------- export / import ----------------
$<HTMLButtonElement>("export-conversation").addEventListener("click", async () => {
  if (!activeConversationId) return;
  const passphrase = window.prompt("Passphrase to encrypt this export with:");
  if (!passphrase) return;
  const panel = $<HTMLDivElement>("export-panel");
  panel.hidden = false;
  panel.replaceChildren(el("div", "row", "Sealing…"));
  try {
    const result = await api.exportConversation(activeConversationId, passphrase);
    panel.replaceChildren();
    const textarea = el("textarea", "invite-field mono") as HTMLTextAreaElement;
    textarea.readOnly = true;
    textarea.rows = 3;
    textarea.value = result.sealed_base64;
    panel.append(textarea);
    const actions = el("div", "actions");
    const copy = el("button", "btn-outline", "Copy");
    copy.type = "button";
    copy.addEventListener("click", async () => {
      await navigator.clipboard.writeText(result.sealed_base64);
      copy.textContent = "Copied";
    });
    actions.append(copy);
    panel.append(actions);
  } catch (err) {
    panel.replaceChildren(el("div", "error-text", errorMessage(err)));
  }
});

// ---------------- payment requests ----------------
$<HTMLButtonElement>("open-payment-request").addEventListener("click", () => {
  $<HTMLDivElement>("payment-panel").hidden = false;
  $<HTMLInputElement>("payment-address").value = "";
  $<HTMLInputElement>("payment-amount").value = "";
  $<HTMLInputElement>("payment-memo").value = "";
  $<HTMLDivElement>("payment-error").hidden = true;
});

$<HTMLButtonElement>("payment-cancel").addEventListener("click", () => {
  $<HTMLDivElement>("payment-panel").hidden = true;
});

$<HTMLButtonElement>("payment-send").addEventListener("click", async (event) => {
  const button = event.currentTarget as HTMLButtonElement;
  if (button.disabled) return;
  if (!activeConversationId) return;
  const asset = $<HTMLSelectElement>("payment-asset").value as PaymentAsset;
  const address = $<HTMLInputElement>("payment-address").value.trim();
  const amount = $<HTMLInputElement>("payment-amount").value.trim();
  const memo = $<HTMLInputElement>("payment-memo").value.trim();
  const errorBox = $<HTMLDivElement>("payment-error");
  errorBox.hidden = true;

  if (!address) {
    errorBox.hidden = false;
    errorBox.textContent = "Enter a recipient address.";
    return;
  }
  button.disabled = true;
  try {
    const { message } = await api.createPaymentRequest(activeConversationId, {
      asset,
      address,
      amount: amount || null,
      memo: memo || null,
    });
    $<HTMLDivElement>("msgs").append(renderMessage(message));
    $<HTMLDivElement>("msgs").scrollTop = $<HTMLDivElement>("msgs").scrollHeight;
    lastMessageCache.set(activeConversationId, message);
    renderConvList();
    $<HTMLDivElement>("payment-panel").hidden = true;
  } catch (err) {
    errorBox.hidden = false;
    errorBox.textContent = errorMessage(err);
  } finally {
    button.disabled = false;
  }
});

$<HTMLButtonElement>("open-import").addEventListener("click", () => {
  $<HTMLDivElement>("screen-import").hidden = false;
  $<HTMLTextAreaElement>("import-bundle").value = "";
  $<HTMLInputElement>("import-passphrase").value = "";
  $<HTMLParagraphElement>("import-status").textContent = "";
});
$<HTMLButtonElement>("close-import").addEventListener("click", () => {
  $<HTMLDivElement>("screen-import").hidden = true;
});
$<HTMLButtonElement>("import-submit").addEventListener("click", async () => {
  const status = $<HTMLParagraphElement>("import-status");
  const sealed = $<HTMLTextAreaElement>("import-bundle").value.trim();
  const passphrase = $<HTMLInputElement>("import-passphrase").value;
  if (!sealed || !passphrase) {
    status.textContent = "Both the bundle and the passphrase are required.";
    return;
  }
  status.textContent = "Importing…";
  try {
    const result = await api.importConversation(passphrase, sealed);
    status.textContent = `Imported ${result.messages_imported} message(s).`;
    await refreshConversations();
    $<HTMLDivElement>("screen-import").hidden = true;
    openConversation(result.conversation_id);
  } catch (err) {
    status.textContent = errorMessage(err);
  }
});

// ---------------- cosmetics store / stickers ----------------

function cosmeticLabel(kind: string): string {
  return kind === "sticker_pack" ? "sticker pack" : kind;
}

async function renderStore() {
  const catalogList = $<HTMLDivElement>("store-catalog-list");
  const inventoryList = $<HTMLDivElement>("store-inventory-list");
  const equippedList = $<HTMLDivElement>("store-equipped-list");
  catalogList.replaceChildren(el("div", "empty-note", "Loading…"));
  inventoryList.replaceChildren();
  equippedList.replaceChildren();

  try {
    const [catalog, inventory, equipped] = await Promise.all([
      api.listCosmeticCatalog(),
      api.listCosmeticInventory(),
      api.listCosmeticsEquipped(),
    ]);
    const owned = new Set(inventory.map((item) => `${item.kind}:${item.item_id}`));

    catalogList.replaceChildren();
    if (catalog.length === 0) catalogList.append(el("div", "empty-note", "Nothing in the catalog yet."));
    for (const item of catalog) {
      const row = el("div", "device-row");
      const info = el("div");
      info.append(el("div", "name", `${item.name} (${cosmeticLabel(item.kind)})`));
      info.append(el("div", "meta mono", `${item.price_amount} ${item.price_asset}`));
      row.append(info);
      const actions = el("div", "actions");
      if (owned.has(`${item.kind}:${item.item_id}`)) {
        actions.append(el("span", "meta mono", "owned"));
      } else {
        const buy = el("button", "chip-btn", "Buy");
        buy.type = "button";
        buy.addEventListener("click", async () => {
          buy.disabled = true;
          try {
            const purchase = await api.purchaseCosmetic(item.item_id);
            if (purchase.checkout_url) {
              window.open(purchase.checkout_url, "_blank", "noopener,noreferrer");
              window.alert("Invoice created. The cosmetic is granted once BTCPay confirms payment.");
            } else {
              window.alert(
                "Purchase draft recorded, but BTCPay is not configured yet. No payment can complete until the operator enables BTCPay.",
              );
            }
          } catch (err) {
            window.alert(errorMessage(err));
          } finally {
            buy.disabled = false;
          }
        });
        actions.append(buy);
      }
      row.append(actions);
      catalogList.append(row);
    }

    if (inventory.length === 0) inventoryList.append(el("div", "empty-note", "Nothing owned yet."));
    for (const item of inventory) {
      const row = el("div", "device-row");
      row.append(el("div", "name", `${item.item_id} (${cosmeticLabel(item.kind)})`));
      const actions = el("div", "actions");
      const equip = el("button", "chip-btn", "Equip");
      equip.type = "button";
      equip.hidden = item.kind === "sticker_pack";
      equip.addEventListener("click", async () => {
        try {
          await api.equipCosmetic(item.kind, item.item_id);
          await renderStore();
          if (item.kind === "theme") applyEquippedTheme();
        } catch (err) {
          window.alert(errorMessage(err));
        }
      });
      actions.append(equip);
      row.append(actions);
      inventoryList.append(row);
    }

    if (equipped.length === 0) equippedList.append(el("div", "empty-note", "Nothing equipped."));
    for (const item of equipped) {
      const row = el("div", "device-row");
      row.append(el("div", "name", `${cosmeticLabel(item.kind)}: ${item.item_id}`));
      const actions = el("div", "actions");
      const unequip = el("button", "chip-btn danger", "Unequip");
      unequip.type = "button";
      unequip.addEventListener("click", async () => {
        try {
          await api.unequipCosmetic(item.kind);
          await renderStore();
        } catch (err) {
          window.alert(errorMessage(err));
        }
      });
      actions.append(unequip);
      row.append(actions);
      equippedList.append(row);
    }
  } catch (err) {
    catalogList.replaceChildren(el("div", "error-text", errorMessage(err)));
  }
}

/// No real theming asset pipeline yet — this just toggles a class so an
/// equipped theme is visibly different, consistent with the store's
/// "cosmetic only" framing.
function applyEquippedTheme() {
  document.body.className = document.body.className.replace(/\btheme-\S+/g, "");
}

$<HTMLButtonElement>("open-store").addEventListener("click", async () => {
  $<HTMLDivElement>("screen-store").hidden = false;
  await renderStore();
});
$<HTMLButtonElement>("close-store").addEventListener("click", () => {
  $<HTMLDivElement>("screen-store").hidden = true;
});

async function renderStickerPicker() {
  const list = $<HTMLDivElement>("sticker-picker-list");
  const empty = $<HTMLParagraphElement>("sticker-picker-empty");
  list.replaceChildren();
  empty.hidden = true;
  try {
    const [packs, inventory] = await Promise.all([api.listStickerPacks(), api.listCosmeticInventory()]);
    const ownedPacks = new Set(
      inventory.filter((item) => item.kind === "sticker_pack").map((item) => item.item_id),
    );
    const sendable = packs.filter((pack) => ownedPacks.has(pack.pack_item_id));
    if (sendable.length === 0) {
      empty.hidden = false;
      return;
    }
    for (const pack of sendable) {
      for (const sticker of pack.stickers) {
        const btn = el("button", "chip-btn", sticker.label);
        btn.type = "button";
        btn.addEventListener("click", async () => {
          if (!activeConversationId) return;
          try {
            const { message } = await api.sendSticker(activeConversationId, sticker.sticker_id);
            $<HTMLDivElement>("msgs").append(renderMessage(message));
            $<HTMLDivElement>("msgs").scrollTop = $<HTMLDivElement>("msgs").scrollHeight;
            $<HTMLDivElement>("sticker-picker").hidden = true;
          } catch (err) {
            window.alert(errorMessage(err));
          }
        });
        list.append(btn);
      }
    }
  } catch (err) {
    list.replaceChildren(el("div", "error-text", errorMessage(err)));
  }
}

$<HTMLButtonElement>("toggle-sticker-picker").addEventListener("click", async () => {
  const picker = $<HTMLDivElement>("sticker-picker");
  picker.hidden = !picker.hidden;
  if (!picker.hidden) await renderStickerPicker();
});

// ---------------- message search (local only) ----------------
let searchDebounceHandle: ReturnType<typeof setTimeout> | null = null;

$<HTMLButtonElement>("open-search").addEventListener("click", () => {
  $<HTMLDivElement>("screen-search").hidden = false;
  $<HTMLInputElement>("search-field").focus();
});
$<HTMLButtonElement>("close-search").addEventListener("click", () => {
  $<HTMLDivElement>("screen-search").hidden = true;
});

$<HTMLInputElement>("search-field").addEventListener("input", (event) => {
  const query = (event.target as HTMLInputElement).value;
  if (searchDebounceHandle) clearTimeout(searchDebounceHandle);
  searchDebounceHandle = setTimeout(() => runMessageSearch(query), 200);
});

async function runMessageSearch(query: string) {
  const results = $<HTMLDivElement>("search-results");
  if (!query.trim()) {
    results.replaceChildren();
    return;
  }
  try {
    const matches = await api.searchMessages(query);
    results.replaceChildren();
    if (matches.length === 0) {
      results.append(el("div", "empty-note", "No matches."));
      return;
    }
    for (const match of matches) {
      const row = el("div", "device-row");
      const info = el("div");
      const snippetEl = el("div", "name");
      // `snippet` brackets matches with [ ] (FTS5's snippet(), never HTML)
      // — render those as <mark> via text nodes, never innerHTML.
      for (const part of match.snippet.split(/(\[[^\]]*\])/)) {
        if (part.startsWith("[") && part.endsWith("]")) {
          const mark = document.createElement("mark");
          mark.textContent = part.slice(1, -1);
          snippetEl.append(mark);
        } else {
          snippetEl.append(document.createTextNode(part));
        }
      }
      info.append(snippetEl);
      info.append(el("div", "meta mono", formatClock(match.sent_at)));
      row.append(info);
      row.addEventListener("click", () => {
        $<HTMLDivElement>("screen-search").hidden = true;
        openConversation(match.conversation_id);
      });
      results.append(row);
    }
  } catch (err) {
    results.replaceChildren(el("div", "error-text", errorMessage(err)));
  }
}

// ---------------- link previews (client-only, opt-in) ----------------
$<HTMLSpanElement>("link-preview-label").textContent = LINK_PREVIEW_SETTING_COPY.label;
$<HTMLParagraphElement>("link-preview-warning").textContent = LINK_PREVIEW_SETTING_COPY.warning;
$<HTMLInputElement>("link-preview-toggle").checked = isLinkPreviewsEnabled();
$<HTMLInputElement>("link-preview-toggle").addEventListener("change", (event) => {
  setLinkPreviewsEnabled((event.target as HTMLInputElement).checked);
});

// ---------------- security overlay ----------------
$<HTMLButtonElement>("open-security").addEventListener("click", async () => {
  $<HTMLDivElement>("screen-security").hidden = false;
  $<HTMLInputElement>("link-preview-toggle").checked = isLinkPreviewsEnabled();
  try {
    const push = await api.getPushRegistration();
    $<HTMLInputElement>("push-toggle").checked = push.enabled;
  } catch {
    // Leave the checkbox at its last known state.
  }
  try {
    const identity = await api.getIdentity();
    $<HTMLElement>("id-signing").textContent = identity.public_signing_key ?? "—";
    $<HTMLElement>("id-agreement").textContent = identity.public_agreement_key ?? "—";
  } catch (err) {
    $<HTMLElement>("id-signing").textContent = errorMessage(err);
  }
  $<HTMLDivElement>("totp-enroll-panel").hidden = true;
  try {
    const { enabled } = await api.getTypingIndicatorSetting();
    $<HTMLInputElement>("typing-indicator-toggle").checked = enabled;
  } catch {
    // Leave the checkbox at its last known state rather than blocking the
    // rest of the security overlay on this.
  }
  try {
    await refreshDeadMansSwitchStatus();
    await refreshDeadMansSwitchReleases();
  } catch {
    // Leave the panel at its last known state.
  }
  await Promise.all([renderDevicesList(), renderLocalAuthStatus()]);
});
$<HTMLInputElement>("typing-indicator-toggle").addEventListener("change", async (event) => {
  const checkbox = event.target as HTMLInputElement;
  try {
    await api.setTypingIndicatorSetting(checkbox.checked);
  } catch (err) {
    checkbox.checked = !checkbox.checked;
    window.alert(errorMessage(err));
  }
});
$<HTMLInputElement>("push-toggle").addEventListener("change", async (event) => {
  const checkbox = event.target as HTMLInputElement;
  try {
    await api.setPushRegistration(checkbox.checked);
  } catch (err) {
    checkbox.checked = !checkbox.checked;
    window.alert(errorMessage(err));
  }
});
$<HTMLButtonElement>("close-security").addEventListener("click", () => {
  $<HTMLDivElement>("screen-security").hidden = true;
});

// ---------------- dead man's switch ----------------
function formatDmsTimestamp(secs: number | null): string {
  return secs === null ? "—" : new Date(secs * 1000).toLocaleString();
}

async function refreshDeadMansSwitchStatus() {
  const status = await api.getDeadMansSwitch();
  $<HTMLInputElement>("dms-toggle").checked = status.enabled;
  $<HTMLInputElement>("dms-cadence").value = String(status.cadence_days || 30);
  $<HTMLElement>("dms-last-checkin").textContent = formatDmsTimestamp(
    status.last_check_in_at || null,
  );
  $<HTMLElement>("dms-deadline").textContent = formatDmsTimestamp(status.next_deadline_at);
  $<HTMLParagraphElement>("dms-triggered-note").hidden = status.triggered_at === null;
}

async function refreshDeadMansSwitchReleases() {
  const { releases } = await api.listDeadMansSwitchReleases();
  const list = $<HTMLDivElement>("dms-release-list");
  list.replaceChildren();
  const select = $<HTMLSelectElement>("dms-add-contact");
  select.replaceChildren();
  for (const contact of contacts) {
    const option = el("option", undefined, contact.display_name || contact.contact_id);
    option.value = contact.contact_id;
    select.append(option);
  }
  if (releases.length === 0) {
    list.append(el("div", "empty-note", "No release messages configured."));
    return;
  }
  for (const release of releases) {
    const row = el("div", "device-row");
    const info = el("div");
    info.append(el("div", "name", release.contact_display_name || release.contact_id));
    info.append(el("div", "meta mono", release.body));
    row.append(info);
    const removeBtn = el("button", "chip-btn", "Remove");
    removeBtn.type = "button";
    removeBtn.addEventListener("click", async () => {
      try {
        await api.removeDeadMansSwitchRelease(release.id);
        await refreshDeadMansSwitchReleases();
      } catch (err) {
        window.alert(errorMessage(err));
      }
    });
    row.append(removeBtn);
    list.append(row);
  }
}

$<HTMLInputElement>("dms-toggle").addEventListener("change", async (event) => {
  const checkbox = event.target as HTMLInputElement;
  const statusEl = $<HTMLParagraphElement>("dms-status");
  if (checkbox.checked) {
    const confirmed = window.confirm(
      "If you don't check in for the configured number of days, Blackhole " +
        "will automatically send your predefined release messages to their " +
        "contacts. Make sure you've added at least one release message " +
        "before relying on this. Continue?",
    );
    if (!confirmed) {
      checkbox.checked = false;
      return;
    }
  }
  const cadence = parseInt($<HTMLInputElement>("dms-cadence").value, 10) || 30;
  try {
    await api.setDeadMansSwitch(checkbox.checked, checkbox.checked ? cadence : undefined);
    statusEl.textContent = "";
    await refreshDeadMansSwitchStatus();
  } catch (err) {
    checkbox.checked = !checkbox.checked;
    statusEl.textContent = errorMessage(err);
  }
});

$<HTMLInputElement>("dms-cadence").addEventListener("change", async (event) => {
  const input = event.target as HTMLInputElement;
  if (!$<HTMLInputElement>("dms-toggle").checked) return; // cadence only meaningful while enabled
  const cadence = parseInt(input.value, 10);
  const statusEl = $<HTMLParagraphElement>("dms-status");
  if (!cadence || cadence < 1) {
    statusEl.textContent = "Cadence must be at least 1 day.";
    return;
  }
  try {
    await api.setDeadMansSwitch(true, cadence);
    statusEl.textContent = "";
    await refreshDeadMansSwitchStatus();
  } catch (err) {
    statusEl.textContent = errorMessage(err);
  }
});

$<HTMLButtonElement>("dms-checkin-now").addEventListener("click", async () => {
  const statusEl = $<HTMLParagraphElement>("dms-status");
  try {
    await api.deadMansSwitchCheckIn();
    statusEl.textContent = "Checked in.";
    await refreshDeadMansSwitchStatus();
  } catch (err) {
    statusEl.textContent = errorMessage(err);
  }
});

$<HTMLButtonElement>("dms-add-release").addEventListener("click", async () => {
  const errorBox = $<HTMLParagraphElement>("dms-release-error");
  errorBox.hidden = true;
  errorBox.textContent = "";
  const contactId = $<HTMLSelectElement>("dms-add-contact").value;
  const body = $<HTMLTextAreaElement>("dms-add-body").value.trim();
  if (!contactId) {
    errorBox.hidden = false;
    errorBox.textContent = "Add a contact first.";
    return;
  }
  if (!body) {
    errorBox.hidden = false;
    errorBox.textContent = "Enter a message body.";
    return;
  }
  try {
    await api.addDeadMansSwitchRelease(contactId, body);
    $<HTMLTextAreaElement>("dms-add-body").value = "";
    await refreshDeadMansSwitchReleases();
  } catch (err) {
    errorBox.hidden = false;
    errorBox.textContent = errorMessage(err);
  }
});

$<HTMLButtonElement>("panic-wipe").addEventListener("click", async () => {
  const wipeStatus = $<HTMLParagraphElement>("wipe-status");
  const confirmed = window.confirm(
    "This irreversibly deletes all local keys and messages. Continue?",
  );
  if (!confirmed) return;

  wipeStatus.textContent = "Wiping…";
  try {
    await api.panicWipe();
    // The daemon has already deleted everything server-side by the time
    // this resolves — the client must not leave any previously-rendered
    // contact/conversation/message content on screen or in memory behind
    // the (still-open) security overlay.
    resetAppState();
    $<HTMLDivElement>("screen-security").hidden = true;
    showOnly("screen-unlock");
    const unlockStatus = $<HTMLParagraphElement>("unlock-status");
    unlockStatus.textContent =
      "Wiped. The daemon has exited — restart it to create a new identity.";
    $<HTMLDivElement>("unlock-actions").replaceChildren();
  } catch (err) {
    wipeStatus.textContent = errorMessage(err);
  }
});

// ---------------- message requests overlay ----------------
$<HTMLButtonElement>("open-requests").addEventListener("click", async () => {
  $<HTMLDivElement>("screen-requests").hidden = false;
  await renderRequestsList();
});
$<HTMLButtonElement>("close-requests").addEventListener("click", () => {
  $<HTMLDivElement>("screen-requests").hidden = true;
});

async function renderRequestsList() {
  const list = $<HTMLDivElement>("requests-list");
  list.replaceChildren(el("div", "empty-note", "Loading…"));
  try {
    const requests = (await api.listMessageRequests()).filter((r) => r.status === "pending");
    list.replaceChildren();
    if (requests.length === 0) {
      list.append(el("div", "empty-note", "No pending requests."));
      return;
    }
    for (const request of requests) {
      const row = el("div", "device-row");
      const info = el("div");
      info.append(el("div", "name", request.contact_id));
      info.append(el("div", "meta mono", new Date(request.received_at * 1000).toLocaleString()));
      row.append(info);

      const actions = el("div", "actions");
      const accept = el("button", "chip-btn", "Accept");
      accept.type = "button";
      accept.addEventListener("click", async () => {
        try {
          await api.acceptMessageRequest(request.contact_id);
          await Promise.all([refreshContacts(), refreshConversations(), refreshRequestsBadge()]);
          await renderRequestsList();
        } catch (err) {
          window.alert(errorMessage(err));
        }
      });
      const decline = el("button", "chip-btn danger", "Decline");
      decline.type = "button";
      decline.addEventListener("click", async () => {
        try {
          await api.declineMessageRequest(request.contact_id);
          await refreshRequestsBadge();
          await renderRequestsList();
        } catch (err) {
          window.alert(errorMessage(err));
        }
      });
      actions.append(accept, decline);
      row.append(actions);
      list.append(row);
    }
  } catch (err) {
    list.replaceChildren(el("div", "error-text", errorMessage(err)));
  }
}

// ---------------- profiles overlay ----------------
$<HTMLButtonElement>("open-profiles").addEventListener("click", async () => {
  $<HTMLDivElement>("screen-profiles").hidden = false;
  await renderProfilesList();
});
$<HTMLButtonElement>("close-profiles").addEventListener("click", () => {
  $<HTMLDivElement>("screen-profiles").hidden = true;
});

async function renderProfilesList() {
  const list = $<HTMLDivElement>("profiles-list");
  list.replaceChildren(el("div", "empty-note", "Loading…"));
  try {
    const [profiles, active] = await Promise.all([api.listProfiles(), api.activeProfile()]);
    list.replaceChildren();
    for (const profile of profiles) {
      list.append(renderProfileRow(profile, profile.id === active.profile_id));
    }
  } catch (err) {
    list.replaceChildren(el("div", "error-text", errorMessage(err)));
  }
}

function renderProfileRow(profile: ProfileMeta, isActive: boolean): HTMLDivElement {
  const row = el("div", "device-row");
  const info = el("div");
  info.append(el("div", "name", profile.display_name));
  info.append(el("div", "meta", isActive ? "active" : "inactive"));
  row.append(info);

  const actions = el("div", "actions");
  if (!isActive) {
    const activate = el("button", "chip-btn", "Activate");
    activate.type = "button";
    activate.addEventListener("click", () => switchProfile(profile.id));
    actions.append(activate);

    const remove = el("button", "chip-btn danger", "Delete");
    remove.type = "button";
    remove.addEventListener("click", async () => {
      const confirmed = window.confirm(`Delete profile "${profile.display_name}"? This is irreversible.`);
      if (!confirmed) return;
      try {
        await api.deleteProfile(profile.id);
        await renderProfilesList();
      } catch (err) {
        window.alert(errorMessage(err));
      }
    });
    actions.append(remove);
  }
  row.append(actions);
  return row;
}

async function switchProfile(profileId: string) {
  try {
    await api.activateProfile(profileId);
  } catch (err) {
    window.alert(errorMessage(err));
    return;
  }
  resetAppState();
  await boot();
}

$<HTMLButtonElement>("create-profile").addEventListener("click", async (event) => {
  const button = event.currentTarget as HTMLButtonElement;
  if (button.disabled) return;
  const input = $<HTMLInputElement>("new-profile-name");
  const name = input.value.trim();
  if (!name) return;
  button.disabled = true;
  try {
    await api.createProfile(name);
    input.value = "";
    await renderProfilesList();
  } catch (err) {
    window.alert(errorMessage(err));
  } finally {
    button.disabled = false;
  }
});

// ---------------- add contact overlay ----------------
$<HTMLButtonElement>("add-contact").addEventListener("click", async () => {
  $<HTMLDivElement>("screen-add-contact").hidden = false;
  $<HTMLTextAreaElement>("invite-input").value = "";
  $<HTMLDivElement>("invite-preview").hidden = true;
  $<HTMLDivElement>("invite-created").hidden = true;
  try {
    await refreshEphemeralIdentities();
  } catch {
    // Leave the list/select at their last known state.
  }
});
$<HTMLButtonElement>("close-add-contact").addEventListener("click", () => {
  $<HTMLDivElement>("screen-add-contact").hidden = true;
});

$<HTMLButtonElement>("invite-decode").addEventListener("click", async () => {
  const link = $<HTMLTextAreaElement>("invite-input").value.trim();
  const preview = $<HTMLDivElement>("invite-preview");
  if (!link) return;

  preview.hidden = false;
  preview.replaceChildren(el("div", "row", "Decoding…"));
  try {
    const decoded = await api.decodeInvite(link);
    preview.replaceChildren();

    const nameRow = el("div", "row");
    nameRow.append(el("span", undefined, "Name"), el("span", undefined, decoded.display_name ?? "(none)"));
    preview.append(nameRow);

    const keyRow = el("div", "row");
    keyRow.append(el("span", undefined, "Key"), el("code", undefined, decoded.identity_signing_key.slice(0, 20) + "…"));
    preview.append(keyRow);

    if (decoded.locally_expired) {
      preview.append(el("div", "error-text", "This invite has expired."));
    }

    const actions = el("div", "actions");
    const addButton = el("button", "btn-primary", "Add contact");
    addButton.type = "button";
    addButton.disabled = decoded.locally_expired;
    addButton.addEventListener("click", () => addDecodedContact(decoded, addButton));
    actions.append(addButton);
    preview.append(actions);
  } catch {
    preview.replaceChildren(el("div", "error-text", "Couldn't decode that link — check it was copied in full."));
  }
});

async function addDecodedContact(
  decoded: Awaited<ReturnType<typeof api.decodeInvite>>,
  button: HTMLButtonElement,
) {
  button.disabled = true;
  try {
    const contactId = decoded.identity_signing_key;
    const identityPublicKey = decoded.identity_signing_key + decoded.identity_agreement_key;
    await api.addContact({
      contact_id: contactId,
      identity_public_key: identityPublicKey,
      display_name: decoded.display_name,
    });
    const conversation = await api.createDirectConversation(contactId);
    await refreshContacts();
    await refreshConversations();
    $<HTMLDivElement>("screen-add-contact").hidden = true;
    openConversation(conversation.conversation_id);
  } catch (err) {
    button.disabled = false;
    window.alert(errorMessage(err));
  }
}

$<HTMLButtonElement>("invite-create").addEventListener("click", async (event) => {
  const button = event.currentTarget as HTMLButtonElement;
  if (button.disabled) return;
  button.disabled = true;
  const created = $<HTMLDivElement>("invite-created");
  created.hidden = false;
  created.replaceChildren(el("div", "row", "Generating…"));
  try {
    const identityId = $<HTMLSelectElement>("invite-identity-select").value || undefined;
    const invite = await api.createInvite(identityId);
    created.replaceChildren();

    const linkRow = el("div", "row");
    linkRow.append(el("span", undefined, "Link"), el("code", undefined, invite.link.slice(0, 28) + "…"));
    created.append(linkRow);

    const actions = el("div", "actions");
    const copy = el("button", "btn-outline", "Copy link");
    copy.type = "button";
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(invite.link);
        copy.textContent = "Copied";
      } catch {
        copy.textContent = "Copy failed";
      }
    });
    const revoke = el("button", "btn-outline", "Revoke");
    revoke.type = "button";
    revoke.addEventListener("click", async () => {
      if (revoke.disabled) return;
      revoke.disabled = true;
      try {
        await api.revokeInvite(invite.token);
        revoke.textContent = "Revoked";
      } catch (err) {
        revoke.disabled = false;
        window.alert(errorMessage(err));
      }
    });
    actions.append(copy, revoke);
    created.append(actions);
  } catch (err) {
    created.replaceChildren(el("div", "error-text", errorMessage(err)));
  } finally {
    button.disabled = false;
  }
});

// ---------------- ephemeral identities ----------------
async function refreshEphemeralIdentities() {
  const identities = await api.listEphemeralIdentities();

  const select = $<HTMLSelectElement>("invite-identity-select");
  const previousValue = select.value;
  select.replaceChildren();
  const realOption = el("option", undefined, "My real identity");
  realOption.value = "";
  select.append(realOption);
  for (const identity of identities) {
    const option = el(
      "option",
      undefined,
      identity.label ? `${identity.label} (expires ${formatEphemeralExpiry(identity.expires_at)})` : `Ephemeral (expires ${formatEphemeralExpiry(identity.expires_at)})`,
    );
    option.value = identity.id;
    select.append(option);
  }
  if (identities.some((i) => i.id === previousValue)) {
    select.value = previousValue;
  }

  const list = $<HTMLDivElement>("ephemeral-identity-list");
  list.replaceChildren();
  if (identities.length === 0) {
    list.append(el("div", "empty-note", "No ephemeral identities yet."));
    return;
  }
  for (const identity of identities) {
    const row = el("div", "device-row");
    const info = el("div");
    info.append(el("div", "name", identity.label || "Ephemeral identity"));
    info.append(el("div", "meta mono", `expires ${formatEphemeralExpiry(identity.expires_at)}`));
    row.append(info);
    const revokeBtn = el("button", "chip-btn danger", "Revoke");
    revokeBtn.type = "button";
    revokeBtn.addEventListener("click", async () => {
      if (revokeBtn.disabled) return;
      revokeBtn.disabled = true;
      try {
        await api.revokeEphemeralIdentity(identity.id);
        await refreshEphemeralIdentities();
      } catch (err) {
        revokeBtn.disabled = false;
        window.alert(errorMessage(err));
      }
    });
    row.append(revokeBtn);
    list.append(row);
  }
}

function formatEphemeralExpiry(secs: number): string {
  return new Date(secs * 1000).toLocaleDateString();
}

$<HTMLButtonElement>("ephemeral-identity-create").addEventListener("click", async (event) => {
  const button = event.currentTarget as HTMLButtonElement;
  if (button.disabled) return;
  const errorBox = $<HTMLParagraphElement>("ephemeral-identity-error");
  errorBox.hidden = true;
  const label = $<HTMLInputElement>("ephemeral-identity-label").value.trim();
  const ttlDays = parseInt($<HTMLInputElement>("ephemeral-identity-ttl").value, 10);
  if (!ttlDays || ttlDays < 1) {
    errorBox.hidden = false;
    errorBox.textContent = "TTL must be at least 1 day.";
    return;
  }
  button.disabled = true;
  try {
    await api.createEphemeralIdentity(label || undefined, ttlDays);
    $<HTMLInputElement>("ephemeral-identity-label").value = "";
    await refreshEphemeralIdentities();
  } catch (err) {
    errorBox.hidden = false;
    errorBox.textContent = errorMessage(err);
  } finally {
    button.disabled = false;
  }
});

// ---------------- new group overlay ----------------
$<HTMLButtonElement>("new-group").addEventListener("click", () => {
  $<HTMLDivElement>("screen-new-group").hidden = false;
  $<HTMLInputElement>("new-group-name").value = "";
  $<HTMLDivElement>("new-group-error").hidden = true;

  const list = $<HTMLDivElement>("new-group-contacts");
  list.replaceChildren();
  if (contacts.length === 0) {
    list.append(el("div", "empty-note", "No contacts yet — add one first."));
    return;
  }
  for (const contact of contacts) {
    const row = el("label", "checkbox-row");
    const checkbox = el("input") as HTMLInputElement;
    checkbox.type = "checkbox";
    checkbox.value = contact.contact_id;
    row.append(checkbox, document.createTextNode(contact.display_name || contact.contact_id));
    list.append(row);
  }
});
$<HTMLButtonElement>("close-new-group").addEventListener("click", () => {
  $<HTMLDivElement>("screen-new-group").hidden = true;
});

$<HTMLButtonElement>("create-group-submit").addEventListener("click", async (event) => {
  const button = event.currentTarget as HTMLButtonElement;
  if (button.disabled) return;
  const name = $<HTMLInputElement>("new-group-name").value.trim();
  const errorBox = $<HTMLDivElement>("new-group-error");
  errorBox.hidden = true;
  const selected = [...$<HTMLDivElement>("new-group-contacts").querySelectorAll<HTMLInputElement>('input[type="checkbox"]:checked')].map(
    (c) => c.value,
  );
  if (selected.length === 0) {
    errorBox.hidden = false;
    errorBox.textContent = "Pick at least one member.";
    return;
  }
  const kind = $<HTMLInputElement>("new-group-broadcast").checked ? "broadcast" : "group";
  button.disabled = true;
  try {
    const created = await api.createGroup(name || null, selected, kind);
    await Promise.all([refreshGroups(), refreshConversations()]);
    $<HTMLDivElement>("screen-new-group").hidden = true;
    $<HTMLInputElement>("new-group-broadcast").checked = false;
    openConversation(created.conversation.conversation_id);
  } catch (err) {
    errorBox.hidden = false;
    errorBox.textContent = errorMessage(err);
  } finally {
    button.disabled = false;
  }
});

// ---------------- group members panel ----------------
$<HTMLButtonElement>("manage-members").addEventListener("click", async () => {
  const conversation = currentConversation();
  if (!conversation?.group_id) return;
  const panel = $<HTMLDivElement>("members-panel");
  panel.hidden = !panel.hidden;
  if (panel.hidden) return;
  await renderMembersPanel(conversation.group_id);
});

async function renderMembersPanel(groupId: string) {
  const list = $<HTMLDivElement>("members-list");
  const select = $<HTMLSelectElement>("add-member-select");
  const errorBox = $<HTMLParagraphElement>("members-error");
  errorBox.hidden = true;
  list.replaceChildren(el("div", "empty-note", "Loading…"));
  try {
    const detail = await api.getGroup(groupId);
    list.replaceChildren();
    const memberIds = new Set(detail.members.map((m) => m.contact_id));
    for (const member of detail.members) {
      const row = el("div", "device-row");
      const contact = contactsById.get(member.contact_id);
      row.append(el("div", "name", contact?.display_name || member.contact_id));
      const actions = el("div", "actions");
      const remove = el("button", "chip-btn danger", "Remove");
      remove.type = "button";
      remove.addEventListener("click", async () => {
        try {
          await api.removeGroupMember(groupId, member.contact_id);
          await renderMembersPanel(groupId);
        } catch (err) {
          errorBox.hidden = false;
          errorBox.textContent = errorMessage(err);
        }
      });
      actions.append(remove);
      row.append(actions);
      list.append(row);
    }

    select.replaceChildren();
    const addable = contacts.filter((c) => !memberIds.has(c.contact_id));
    for (const contact of addable) {
      const option = el("option", undefined, contact.display_name || contact.contact_id);
      option.value = contact.contact_id;
      select.append(option);
    }
    $<HTMLButtonElement>("add-member-submit").disabled = addable.length === 0;
  } catch (err) {
    list.replaceChildren(el("div", "error-text", errorMessage(err)));
  }
}

$<HTMLButtonElement>("add-member-submit").addEventListener("click", async () => {
  const conversation = currentConversation();
  if (!conversation?.group_id) return;
  const select = $<HTMLSelectElement>("add-member-select");
  const contactId = select.value;
  if (!contactId) return;
  const errorBox = $<HTMLParagraphElement>("members-error");
  try {
    await api.addGroupMember(conversation.group_id, contactId);
    await renderMembersPanel(conversation.group_id);
  } catch (err) {
    errorBox.hidden = false;
    errorBox.textContent = errorMessage(err);
  }
});

$<HTMLButtonElement>("verify-group-crypto").addEventListener("click", async () => {
  const conversation = currentConversation();
  if (!conversation?.group_id) return;
  const button = $<HTMLButtonElement>("verify-group-crypto");
  const original = button.textContent;
  button.disabled = true;
  try {
    const result = await api.mlsSelfTest(conversation.group_id);
    window.alert(
      result.roundtrip_ok
        ? `MLS round trip confirmed for ${result.confirmed_members.length} member(s).`
        : `Partial round trip — confirmed: ${result.confirmed_members.join(", ") || "none"}.`,
    );
  } catch (err) {
    window.alert(errorMessage(err));
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
});

// ---------------- devices / local unlock (security overlay) ----------------
async function renderDevicesList() {
  const list = $<HTMLDivElement>("devices-list");
  list.replaceChildren(el("div", "empty-note", "Loading…"));
  try {
    const devices = await api.listDevices();
    list.replaceChildren();
    if (devices.length === 0) {
      list.append(el("div", "empty-note", "No linked devices yet."));
      return;
    }
    for (const device of devices) {
      list.append(renderDeviceRow(device));
    }
  } catch (err) {
    list.replaceChildren(el("div", "error-text", errorMessage(err)));
  }
}

function renderDeviceRow(device: Device): HTMLDivElement {
  const row = el("div", "device-row");
  const info = el("div");
  info.append(el("div", "name", device.name || device.device_id.slice(0, 12) + "…"));
  info.append(
    el(
      "div",
      "meta mono",
      device.revoked_at ? "revoked" : new Date(device.linked_at * 1000).toLocaleString(),
    ),
  );
  row.append(info);

  const actions = el("div", "actions");
  if (!device.revoked_at) {
    const badge = el("span", "meta mono", "");
    actions.append(badge);
    refreshDeviceSyncBadge(device.device_id, badge);

    const sync = el("button", "chip-btn", "Sync now");
    sync.type = "button";
    sync.addEventListener("click", async () => {
      sync.disabled = true;
      try {
        await api.syncDevice(device.device_id);
        await refreshDeviceSyncBadge(device.device_id, badge);
      } catch (err) {
        window.alert(errorMessage(err));
      } finally {
        sync.disabled = false;
      }
    });
    actions.append(sync);

    const revoke = el("button", "chip-btn danger", "Revoke");
    revoke.type = "button";
    revoke.addEventListener("click", async () => {
      try {
        await api.revokeDevice(device.device_id);
        await renderDevicesList();
      } catch (err) {
        window.alert(errorMessage(err));
      }
    });
    actions.append(revoke);
  }
  row.append(actions);
  return row;
}

// Local simulation, like the rest of device linking — see index.html's
// device-linking disclosure copy.
async function refreshDeviceSyncBadge(deviceId: string, badge: HTMLElement) {
  try {
    const status = await api.deviceSyncStatus(deviceId);
    badge.textContent =
      status.pending_count > 0 ? `${status.pending_count} pending` : "up to date";
  } catch {
    badge.textContent = "";
  }
}

$<HTMLButtonElement>("link-device").addEventListener("click", async () => {
  const status = $<HTMLParagraphElement>("link-status");
  const button = $<HTMLButtonElement>("link-device");
  button.disabled = true;
  try {
    status.textContent = "Beginning link session…";
    const begun = await api.beginDeviceLink();

    status.textContent = "Scanning link (local simulation)…";
    const scanned = await api.scanDeviceLink(begun.link);

    status.textContent = "Accepting on the trusted device…";
    const accepted = await api.acceptDeviceLink(
      begun.session_id,
      scanned.provisioning_request_b64,
      "New Device",
    );

    status.textContent = "Finishing on the new device…";
    const finished = await api.finishDeviceLink(
      scanned.new_device_session_id,
      accepted.response_ciphertext_b64,
    );

    status.textContent = finished.confirmed
      ? "Linked — a new device row was added below."
      : "Linking completed but identity confirmation failed.";
    await renderDevicesList();
  } catch (err) {
    status.textContent = errorMessage(err);
  } finally {
    button.disabled = false;
  }
});

async function renderLocalAuthStatus() {
  const el2 = $<HTMLParagraphElement>("local-auth-status");
  try {
    const status = await api.localAuthStatus();
    el2.textContent = `TOTP: ${status.totp_enrolled ? "enrolled" : "not enrolled"} · Passkey: ${
      status.passkey_enrolled ? "enrolled" : "not enrolled"
    }`;
    $<HTMLButtonElement>("remove-totp").hidden = !status.totp_enrolled;
  } catch (err) {
    el2.textContent = errorMessage(err);
  }
  await renderPasskeyList();
  await renderDbLockStatus();
}

async function renderPasskeyList() {
  const list = $<HTMLDivElement>("passkey-list");
  try {
    const passkeys = await api.passkeyList();
    list.replaceChildren();
    for (const passkey of passkeys) {
      const row = el("div", "row");
      row.append(
        el("span", undefined, passkey.label || passkey.credential_id.slice(0, 12)),
      );
      const remove = el("button", "chip-btn", "Remove");
      remove.type = "button";
      remove.addEventListener("click", async () => {
        if (!window.confirm("Remove this passkey?")) return;
        remove.disabled = true;
        try {
          await api.passkeyDelete(passkey.credential_id);
          await renderLocalAuthStatus();
        } catch (err) {
          window.alert(errorMessage(err));
          remove.disabled = false;
        }
      });
      row.append(remove);
      list.append(row);
    }
  } catch (err) {
    list.replaceChildren(el("div", "error-text", errorMessage(err)));
  }
}

$<HTMLButtonElement>("enroll-totp").addEventListener("click", async () => {
  const panel = $<HTMLDivElement>("totp-enroll-panel");
  panel.hidden = false;
  panel.replaceChildren(el("div", "row", "Generating…"));
  try {
    const enroll = await api.totpEnrollStart();
    panel.replaceChildren();

    const qr = el("div");
    qr.innerHTML = enroll.qr_svg;
    panel.append(qr);

    const secretRow = el("div", "row");
    secretRow.append(el("span", undefined, "Secret"), el("code", undefined, enroll.base32_secret));
    panel.append(secretRow);

    const codeInput = el("input", "field wide") as HTMLInputElement;
    codeInput.placeholder = "6-digit code from your authenticator app";
    codeInput.style.marginTop = "8px";
    panel.append(codeInput);

    const confirm = el("button", "btn-primary wide", "Confirm");
    confirm.type = "button";
    confirm.style.marginTop = "8px";
    confirm.addEventListener("click", async () => {
      try {
        await api.totpEnrollConfirm(enroll.ceremony_id, codeInput.value.trim());
        panel.hidden = true;
        await renderLocalAuthStatus();
      } catch (err) {
        window.alert(errorMessage(err));
      }
    });
    panel.append(confirm);
  } catch (err) {
    panel.replaceChildren(el("div", "error-text", errorMessage(err)));
  }
});

$<HTMLButtonElement>("remove-totp").addEventListener("click", async () => {
  if (!window.confirm("Remove TOTP unlock?")) return;
  try {
    await api.totpDelete();
    await renderLocalAuthStatus();
  } catch (err) {
    window.alert(errorMessage(err));
  }
});

async function renderDbLockStatus() {
  const statusEl = $<HTMLParagraphElement>("db-lock-status");
  const enableBtn = $<HTMLButtonElement>("enable-db-lock");
  const disableBtn = $<HTMLButtonElement>("disable-db-lock");
  try {
    const [dbPin, gate] = await Promise.all([api.dbPinStatus(), getPrfUnlockConfig()]);
    const locked = dbPin.pin_set && gate !== null;
    statusEl.textContent = locked
      ? "Enabled — the daemon needs your passkey to open the database."
      : dbPin.pin_set
        ? "A manual database PIN is set, but not via this passkey gate."
        : "Not enabled.";
    enableBtn.hidden = locked || dbPin.pin_set;
    disableBtn.hidden = !locked;
  } catch (err) {
    statusEl.textContent = errorMessage(err);
  }
}

$<HTMLButtonElement>("enable-db-lock").addEventListener("click", async () => {
  const button = $<HTMLButtonElement>("enable-db-lock");
  button.disabled = true;
  try {
    // Reuses the daemon's own passkey relying-party id (from the regular
    // local-unlock ceremony start) rather than a dedicated endpoint —
    // the ceremony state it also creates server-side is simply never
    // finished, which is harmless (bounded, in-memory, cleared on
    // restart), not a new endpoint worth adding just for one field.
    const { challenge_json } = await api.passkeyRegisterStart();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rpId = (challenge_json as any).publicKey.rp.id as string;
    const secret = await enrollDatabaseUnlockGate(rpId);
    await api.setDbPin(bytesToHex(secret));
    window.alert(
      "Database lock enabled. The daemon will ask for this passkey the next time it starts.",
    );
    await renderDbLockStatus();
  } catch (err) {
    window.alert(errorMessage(err));
  } finally {
    button.disabled = false;
  }
});

$<HTMLButtonElement>("disable-db-lock").addEventListener("click", async () => {
  const button = $<HTMLButtonElement>("disable-db-lock");
  const gate = await getPrfUnlockConfig().catch(() => null);
  if (!gate) {
    window.alert("No database lock is configured.");
    return;
  }
  button.disabled = true;
  try {
    const secret = await derivePrfSecret(gate);
    if (!secret) throw new Error("Your authenticator did not return a PRF result.");
    await api.clearDbPin(bytesToHex(secret));
    await clearPrfUnlockConfig();
    window.alert("Database lock disabled.");
    await renderDbLockStatus();
  } catch (err) {
    window.alert(errorMessage(err));
  } finally {
    button.disabled = false;
  }
});

$<HTMLButtonElement>("enroll-passkey").addEventListener("click", async () => {
  try {
    const { ceremony_id, challenge_json } = await api.passkeyRegisterStart();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const publicKey = (challenge_json as any).publicKey;
    const options = {
      publicKey: {
        ...publicKey,
        challenge: base64urlToBuffer(publicKey.challenge),
        user: { ...publicKey.user, id: base64urlToBuffer(publicKey.user.id) },
        excludeCredentials: (publicKey.excludeCredentials ?? []).map((c: { id: string }) => ({
          ...c,
          id: base64urlToBuffer(c.id),
        })),
      },
    } as CredentialCreationOptions;
    const credential = (await navigator.credentials.create(options)) as PublicKeyCredential;
    const response = credential.response as AuthenticatorAttestationResponse;
    const credentialJson = {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: bufferToBase64url(response.clientDataJSON),
        attestationObject: bufferToBase64url(response.attestationObject),
      },
    };
    await api.passkeyRegisterFinish(ceremony_id, credentialJson);
    await renderLocalAuthStatus();
    window.alert("Passkey enrolled.");
  } catch (err) {
    window.alert(errorMessage(err));
  }
});

// ---------------- boot ----------------
window.addEventListener("DOMContentLoaded", () => {
  installBlurOnUnfocus($("app"));
  setInterval(pruneExpiredMessages, 5_000);
  setInterval(() => void pollIncomingNetworkCalls(), 3_000);
  boot();
});
