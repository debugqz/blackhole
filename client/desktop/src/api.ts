import { invoke } from "@tauri-apps/api/core";

interface DaemonResponse {
  status: number;
  body: string;
}

export class DaemonError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function call<T>(method: string, path: string, payload?: unknown): Promise<T> {
  const res = await invoke<DaemonResponse>("daemon_call", {
    method,
    path,
    body: payload === undefined ? null : JSON.stringify(payload),
  });
  if (res.status < 200 || res.status >= 300) {
    throw new DaemonError(res.status, res.body || `daemon returned HTTP ${res.status}`);
  }
  if (!res.body) return undefined as T;
  return JSON.parse(res.body) as T;
}

export interface IdentityStatus {
  initialized: boolean;
  public_signing_key: string | null;
  public_agreement_key: string | null;
}

export interface CreateIdentityResponse {
  public_signing_key: string;
  public_agreement_key: string;
  seed_phrase: string;
}

export interface Contact {
  contact_id: string;
  display_name: string | null;
  verified: boolean;
  blocked: boolean;
  added_at: number;
}

export type ConversationKind = "direct" | "group" | "self";

export interface Conversation {
  conversation_id: string;
  kind: ConversationKind;
  contact_id: string | null;
  group_id: string | null;
  created_at: number;
  disappearing_timer_secs: number | null;
}

export interface Message {
  message_id: string;
  conversation_id: string;
  sender_contact_id: string | null;
  body: string | null;
  sent_at: number;
  received_at: number | null;
  expires_at: number | null;
  deleted_at: number | null;
  reply_to_message_id: string | null;
  edited_at: number | null;
}

export interface MessageSearchResult {
  message_id: string;
  conversation_id: string;
  sent_at: number;
  snippet: string;
}

export interface MessageEdit {
  id: number;
  message_id: string;
  body: string | null;
  edited_at: number;
}

export interface SafetyNumberResponse {
  digits: string;
  grouped: string;
  qr_svg: string;
}

export interface DecodedInvite {
  identity_signing_key: string;
  identity_agreement_key: string;
  display_name: string | null;
  expires_at: number | null;
  locally_expired: boolean;
}

export interface CreateInviteResponse {
  link: string;
  qr_svg: string;
  token: string;
  expires_at: number | null;
}

export type MessageRequestStatus = "pending" | "accepted" | "declined";

export interface MessageRequest {
  contact_id: string;
  received_at: number;
  status: MessageRequestStatus;
}

export interface ReportBundle {
  contact_id: string;
  reason: string;
  created_at: number;
  messages: Message[];
}

export interface ProfileMeta {
  id: string;
  display_name: string;
  created_at: number;
}

export interface Reaction {
  message_id: string;
  contact_id: string | null;
  emoji: string;
  reacted_at: number;
}

export type ReceiptStatus = "delivered" | "read";

export interface MessageReceipt {
  message_id: string;
  contact_id: string;
  status: ReceiptStatus;
  updated_at: number;
}

export type PaymentAsset = "XMR" | "BTC" | "ETH";

export interface PaymentRequest {
  message_id: string;
  asset: PaymentAsset;
  address: string;
  amount: string | null;
  memo: string | null;
  paid_at: number | null;
}

export interface PaymentRequestView extends PaymentRequest {
  privacy_label: string;
  qr_svg: string;
}

export interface ExportResponse {
  sealed_base64: string;
}

export interface ImportResponse {
  conversation_id: string;
  messages_imported: number;
}

// ---------------- device linking (local simulation) ----------------

export type DeviceOwner = "self" | "contact";

export interface Device {
  device_id: string;
  owner: DeviceOwner;
  contact_id: string | null;
  name: string | null;
  public_key: string;
  linked_at: number;
  last_seen_at: number | null;
  revoked_at: number | null;
}

export interface BeginLinkResponse {
  session_id: string;
  link: string;
  qr_svg: string;
}

export interface ScanLinkResponse {
  new_device_session_id: string;
  provisioning_request_b64: string;
}

export interface AcceptLinkResponse {
  response_ciphertext_b64: string;
  device: Device;
}

export interface FinishLinkResponse {
  confirmed: boolean;
  device_signing_key_hex: string;
}

// ---------------- device sync (local simulation) ----------------

export interface SyncedMessage {
  message_id: string;
  conversation_id: string;
  sender_contact_id: string | null;
  body: string | null;
  sent_at: number;
  ratchet_roundtrip_ok: boolean;
}

export interface DeviceSyncResponse {
  device_id: string;
  synced: SyncedMessage[];
  cursor_sent_at: number;
  cursor_message_id: string | null;
}

export interface DeviceSyncStatusResponse {
  device_id: string;
  cursor_sent_at: number;
  cursor_message_id: string | null;
  pending_count: number;
}

// ---------------- local unlock (passkey / TOTP) ----------------

export interface LocalAuthStatus {
  passkey_enrolled: boolean;
  totp_enrolled: boolean;
}

export interface DbPinStatus {
  pin_set: boolean;
}

export interface TotpEnrollStartResponse {
  ceremony_id: string;
  provisioning_uri: string;
  qr_svg: string;
  base32_secret: string;
}

export interface PasskeyCeremonyResponse {
  ceremony_id: string;
  challenge_json: unknown;
}

export interface PasskeyCredentialPublic {
  credential_id: string;
  label: string | null;
  enrolled_at: number;
}

// ---------------- groups (MLS) ----------------

export interface GroupDTO {
  group_id: string;
  name: string | null;
  epoch: number;
  created_at: number;
  broadcast_only: boolean;
}

export interface GroupMemberDTO {
  group_id: string;
  contact_id: string;
  joined_at: number;
}

export interface CreateGroupResponse {
  conversation: Conversation;
  group: GroupDTO;
  members: GroupMemberDTO[];
}

export interface GroupDetail {
  group: GroupDTO;
  members: GroupMemberDTO[];
}

export interface MlsSelfTestResponse {
  roundtrip_ok: boolean;
  confirmed_members: string[];
}

// ---------------- cosmetics store (SPEC.md §12: cosmetic-only, crypto-paid, never a privacy upsell) ----------------

export type CosmeticKind = "banner" | "theme" | "badge" | "sticker_pack";

export interface CosmeticCatalogItem {
  item_id: string;
  kind: CosmeticKind;
  name: string;
  description: string | null;
  asset_ref: string;
  price_asset: "XMR" | "BTC" | "ETH";
  price_amount: string;
  active: boolean;
}

export interface CosmeticInventoryItem {
  entitlement_token: string;
  item_id: string;
  kind: CosmeticKind;
  granted_at: number;
}

export interface EquippedCosmetic {
  kind: CosmeticKind;
  item_id: string;
  equipped_at: number;
}

export interface Purchase {
  purchase_id: string;
  item_id: string;
  invoice_id: string;
  asset: "XMR" | "BTC" | "ETH";
  amount: string;
  status: "pending" | "paid" | "expired";
  entitlement_token: string | null;
  created_at: number;
  paid_at: number | null;
  checkout_url: string | null;
  expires_at: number | null;
  provider: string;
  provider_status: string;
}

// ---------------- sticker packs (SPEC.md §12/§15) ----------------

export interface StickerDef {
  sticker_id: string;
  label: string;
}

export interface StickerPackDef {
  pack_item_id: string;
  stickers: StickerDef[];
}

export interface MessageSticker {
  message_id: string;
  pack_item_id: string;
  sticker_id: string;
}

export interface SendStickerResponse {
  message: Message;
  sticker: MessageSticker;
}

// ---------------- file/media attachments ----------------

export type AttachmentKind = "file" | "voice";

export interface FileMetaPublic {
  content_hash: string;
  message_id: string | null;
  file_name: string | null;
  mime_type: string | null;
  size_bytes: number;
  chunk_count: number;
  attachment_kind: AttachmentKind;
  duration_secs: number | null;
}

export interface UploadAttachmentResponse {
  message: Message;
  file: FileMetaPublic;
}

export interface DownloadAttachmentResponse {
  data_base64: string;
  file_name: string | null;
  mime_type: string | null;
}

// ---------------- calls ----------------
// `CallSignal` (`bh_crypto::envelope::CallSignal`) is an opaque, tagged
// blob (WebRTC offer/answer plus the SFrame key-agreement material) —
// this client only ever ferries it between `start_call`/`accept_call`/
// `complete_call`, never inspects its contents, so `unknown` is the
// honest type here rather than a partial reimplementation of its shape.
export type CallSignal = unknown;

export interface CallSignalResponse {
  signal: CallSignal;
}

export interface GroupCallStartedResponse {
  call_id: string;
  local_tag: number;
  participant_tags: number[];
}

export const api = {
  health: () => call<{ status: string; version: string }>("GET", "/health"),

  getIdentity: () => call<IdentityStatus>("GET", "/identity"),
  createIdentity: () => call<CreateIdentityResponse>("POST", "/identity"),

  panicWipe: () => call<void>("POST", "/panic-wipe"),

  listContacts: () => call<Contact[]>("GET", "/contacts"),
  addContact: (req: { contact_id: string; identity_public_key: string; display_name?: string | null }) =>
    call<void>("POST", "/contacts", req),

  listConversations: () => call<Conversation[]>("GET", "/conversations"),
  searchMessages: (query: string, conversationId?: string | null, limit?: number) => {
    const params = new URLSearchParams({ q: query });
    if (conversationId) params.set("conversation_id", conversationId);
    if (limit) params.set("limit", String(limit));
    return call<MessageSearchResult[]>("GET", `/search?${params.toString()}`);
  },
  createDirectConversation: (contactId: string) =>
    call<Conversation>("POST", "/conversations", { contact_id: contactId }),

  listMessages: (conversationId: string) =>
    call<Message[]>("GET", `/conversations/${encodeURIComponent(conversationId)}/messages`),
  sendMessage: (conversationId: string, body: string, replyToMessageId?: string | null) =>
    call<{ message: Message }>(
      "POST",
      `/conversations/${encodeURIComponent(conversationId)}/messages`,
      { body, reply_to_message_id: replyToMessageId ?? null },
    ),
  editMessage: (conversationId: string, messageId: string, body: string) =>
    call<{ message: Message }>(
      "PATCH",
      `/conversations/${encodeURIComponent(conversationId)}/messages/${encodeURIComponent(messageId)}`,
      { body },
    ),
  listMessageEdits: (conversationId: string, messageId: string) =>
    call<{ edits: MessageEdit[] }>(
      "GET",
      `/conversations/${encodeURIComponent(conversationId)}/messages/${encodeURIComponent(messageId)}/edits`,
    ),

  getSafetyNumber: (contactId: string) =>
    call<SafetyNumberResponse>("GET", `/contacts/${encodeURIComponent(contactId)}/safety-number`),
  setVerified: (contactId: string, verified: boolean) =>
    call<void>("POST", `/contacts/${encodeURIComponent(contactId)}/verify`, { verified }),

  decodeInvite: (link: string) => call<DecodedInvite>("POST", "/invites/decode", { link }),
  createInvite: () => call<CreateInviteResponse>("POST", "/invites", {}),
  revokeInvite: (token: string) => call<void>("POST", `/invites/${encodeURIComponent(token)}/revoke`),

  blockContact: (contactId: string) => call<void>("POST", `/contacts/${encodeURIComponent(contactId)}/block`),
  unblockContact: (contactId: string) => call<void>("POST", `/contacts/${encodeURIComponent(contactId)}/unblock`),

  listMessageRequests: () => call<MessageRequest[]>("GET", "/message-requests"),
  acceptMessageRequest: (contactId: string) =>
    call<void>("POST", `/message-requests/${encodeURIComponent(contactId)}/accept`),
  declineMessageRequest: (contactId: string) =>
    call<void>("POST", `/message-requests/${encodeURIComponent(contactId)}/decline`),

  createReport: (req: { contact_id: string; reason: string; message_ids: string[] }) =>
    call<ReportBundle>("POST", "/reports", req),

  listProfiles: () => call<ProfileMeta[]>("GET", "/profiles"),
  activeProfile: () => call<{ profile_id: string }>("GET", "/profiles/active"),
  createProfile: (displayName: string) =>
    call<ProfileMeta>("POST", "/profiles", { display_name: displayName }),
  activateProfile: (profileId: string) =>
    call<void>("POST", `/profiles/${encodeURIComponent(profileId)}/activate`),
  deleteProfile: (profileId: string) => call<void>("DELETE", `/profiles/${encodeURIComponent(profileId)}`),

  listReactions: (messageId: string) =>
    call<Reaction[]>("GET", `/messages/${encodeURIComponent(messageId)}/reactions`),
  addReaction: (messageId: string, emoji: string) =>
    call<void>("POST", `/messages/${encodeURIComponent(messageId)}/reactions`, { emoji }),
  removeReaction: (messageId: string, emoji: string) =>
    call<void>(
      "DELETE",
      `/messages/${encodeURIComponent(messageId)}/reactions/${encodeURIComponent(emoji)}`,
    ),

  listReceipts: (messageId: string) =>
    call<MessageReceipt[]>("GET", `/messages/${encodeURIComponent(messageId)}/receipts`),
  recordReceipt: (messageId: string, contactId: string, status: ReceiptStatus) =>
    call<void>("POST", `/messages/${encodeURIComponent(messageId)}/receipts`, {
      contact_id: contactId,
      status,
    }),

  createPaymentRequest: (
    conversationId: string,
    req: { asset: PaymentAsset; address: string; amount?: string | null; memo?: string | null },
  ) =>
    call<{ message: Message; payment_request: PaymentRequestView }>(
      "POST",
      `/conversations/${encodeURIComponent(conversationId)}/payment-requests`,
      { amount: null, memo: null, ...req },
    ),
  getPaymentRequest: (messageId: string) =>
    call<PaymentRequestView>("GET", `/messages/${encodeURIComponent(messageId)}/payment-request`),
  markPaymentRequestPaid: (messageId: string) =>
    call<void>("POST", `/messages/${encodeURIComponent(messageId)}/payment-request/paid`, {
      confirmed_out_of_band: true,
    }),
  unmarkPaymentRequestPaid: (messageId: string) =>
    call<void>("DELETE", `/messages/${encodeURIComponent(messageId)}/payment-request/paid`),

  setDisappearingTimer: (conversationId: string, timerSecs: number | null) =>
    call<void>(
      "POST",
      `/conversations/${encodeURIComponent(conversationId)}/disappearing-timer`,
      { timer_secs: timerSecs },
    ),

  exportConversation: (conversationId: string, passphrase: string) =>
    call<ExportResponse>(
      "POST",
      `/conversations/${encodeURIComponent(conversationId)}/export`,
      { passphrase },
    ),
  importConversation: (passphrase: string, sealedBase64: string) =>
    call<ImportResponse>("POST", "/conversations/import", {
      passphrase,
      sealed_base64: sealedBase64,
    }),

  // ---------------- device linking (local simulation) ----------------
  listDevices: () => call<Device[]>("GET", "/devices"),
  revokeDevice: (deviceId: string) => call<void>("POST", `/devices/${encodeURIComponent(deviceId)}/revoke`),
  beginDeviceLink: () => call<BeginLinkResponse>("POST", "/devices/link/begin", {}),
  scanDeviceLink: (link: string) => call<ScanLinkResponse>("POST", "/devices/link/scan", { link }),
  acceptDeviceLink: (sessionId: string, provisioningRequestB64: string, deviceName?: string | null) =>
    call<AcceptLinkResponse>("POST", `/devices/link/${encodeURIComponent(sessionId)}/accept`, {
      provisioning_request_b64: provisioningRequestB64,
      device_name: deviceName ?? null,
    }),
  finishDeviceLink: (newDeviceSessionId: string, responseCiphertextB64: string) =>
    call<FinishLinkResponse>(
      "POST",
      `/devices/link/${encodeURIComponent(newDeviceSessionId)}/finish`,
      { response_ciphertext_b64: responseCiphertextB64 },
    ),

  // ---------------- device sync (local simulation) ----------------
  syncDevice: (deviceId: string) => call<DeviceSyncResponse>("GET", `/devices/${encodeURIComponent(deviceId)}/sync`),
  deviceSyncStatus: (deviceId: string) =>
    call<DeviceSyncStatusResponse>("GET", `/devices/${encodeURIComponent(deviceId)}/sync/status`),

  // ---------------- local unlock (passkey / TOTP) ----------------
  localAuthStatus: () => call<LocalAuthStatus>("GET", "/local-auth/status"),
  totpEnrollStart: () => call<TotpEnrollStartResponse>("POST", "/local-auth/totp/enroll/start", {}),
  totpEnrollConfirm: (ceremonyId: string, code: string) =>
    call<void>("POST", "/local-auth/totp/enroll/confirm", { ceremony_id: ceremonyId, code }),
  totpVerify: (code: string) => call<void>("POST", "/local-auth/totp/verify", { code }),
  totpDelete: () => call<void>("DELETE", "/local-auth/totp"),
  passkeyRegisterStart: () =>
    call<PasskeyCeremonyResponse>("POST", "/local-auth/passkey/register/start", {}),
  passkeyRegisterFinish: (ceremonyId: string, credentialJson: unknown, label?: string | null) =>
    call<void>("POST", "/local-auth/passkey/register/finish", {
      ceremony_id: ceremonyId,
      credential_json: credentialJson,
      label: label ?? null,
    }),
  passkeyList: () => call<PasskeyCredentialPublic[]>("GET", "/local-auth/passkey"),
  passkeyAuthStart: () => call<PasskeyCeremonyResponse>("POST", "/local-auth/passkey/auth/start", {}),
  passkeyAuthFinish: (ceremonyId: string, credentialJson: unknown) =>
    call<void>("POST", "/local-auth/passkey/auth/finish", {
      ceremony_id: ceremonyId,
      credential_json: credentialJson,
    }),
  passkeyDelete: (credentialId: string) =>
    call<void>("DELETE", `/local-auth/passkey/${encodeURIComponent(credentialId)}`),

  // ---------------- database PIN (THREAT_MODEL.md §3.7) ----------------
  dbPinStatus: () => call<DbPinStatus>("GET", "/security/db-pin"),
  setDbPin: (pin: string) => call<void>("POST", "/security/db-pin", { pin }),
  clearDbPin: (pin: string) => call<void>("POST", "/security/db-pin/clear", { pin }),

  // ---------------- groups (MLS) ----------------
  listGroups: () => call<GroupDTO[]>("GET", "/groups"),
  createGroup: (
    name: string | null,
    memberContactIds: string[],
    kind?: "group" | "broadcast",
  ) =>
    call<CreateGroupResponse>("POST", "/groups", {
      name,
      member_contact_ids: memberContactIds,
      kind: kind ?? null,
    }),
  getGroup: (groupId: string) => call<GroupDetail>("GET", `/groups/${encodeURIComponent(groupId)}`),
  addGroupMember: (groupId: string, contactId: string) =>
    call<void>("POST", `/groups/${encodeURIComponent(groupId)}/members`, { contact_id: contactId }),
  removeGroupMember: (groupId: string, contactId: string) =>
    call<void>(
      "DELETE",
      `/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(contactId)}`,
    ),
  mlsSelfTest: (groupId: string) =>
    call<MlsSelfTestResponse>("POST", `/groups/${encodeURIComponent(groupId)}/mls-self-test`, {}),

  // ---------------- push wake notifications (opt-in) ----------------
  getPushRegistration: () =>
    call<{ enabled: boolean; token?: string }>("GET", "/push/register"),
  setPushRegistration: (enabled: boolean) =>
    call<{ enabled: boolean; token?: string }>("POST", "/push/register", { enabled }),

  // ---------------- typing indicators (opt-in) ----------------
  getTypingIndicatorSetting: () =>
    call<{ enabled: boolean }>("GET", "/settings/typing-indicators"),
  setTypingIndicatorSetting: (enabled: boolean) =>
    call<void>("POST", "/settings/typing-indicators", { enabled }),
  sendTypingPing: (conversationId: string) =>
    call<{ sent: boolean; ciphertext_len: number | null }>(
      "POST",
      `/conversations/${encodeURIComponent(conversationId)}/typing`,
      {},
    ),
  getTypingStatus: (conversationId: string) =>
    call<{ typing: boolean; contact_id: string | null }>(
      "GET",
      `/conversations/${encodeURIComponent(conversationId)}/typing`,
    ),

  // ---------------- cosmetics store ----------------
  listCosmeticCatalog: () => call<CosmeticCatalogItem[]>("GET", "/cosmetics/catalog"),
  listCosmeticInventory: () => call<CosmeticInventoryItem[]>("GET", "/cosmetics/inventory"),
  listCosmeticsEquipped: () => call<EquippedCosmetic[]>("GET", "/cosmetics/equipped"),
  equipCosmetic: (kind: CosmeticKind, itemId: string) =>
    call<void>("POST", "/cosmetics/equip", { kind, item_id: itemId }),
  unequipCosmetic: (kind: CosmeticKind) =>
    call<void>("DELETE", `/cosmetics/equipped/${encodeURIComponent(kind)}`),
  purchaseCosmetic: (itemId: string) =>
    call<Purchase>("POST", "/cosmetics/purchases", { item_id: itemId }),

  // ---------------- sticker packs ----------------
  listStickerPacks: () => call<StickerPackDef[]>("GET", "/cosmetics/sticker-packs"),
  sendSticker: (conversationId: string, stickerId: string, replyToMessageId?: string | null) =>
    call<SendStickerResponse>(
      "POST",
      `/conversations/${encodeURIComponent(conversationId)}/stickers`,
      { sticker_id: stickerId, reply_to_message_id: replyToMessageId ?? null },
    ),
  getMessageSticker: (messageId: string) =>
    call<MessageSticker>("GET", `/messages/${encodeURIComponent(messageId)}/sticker`),

  // ---------------- file/media attachments ----------------
  listAttachments: (conversationId: string) =>
    call<FileMetaPublic[]>("GET", `/conversations/${encodeURIComponent(conversationId)}/attachments`),
  uploadAttachment: (
    conversationId: string,
    req: {
      file_name?: string | null;
      mime_type?: string | null;
      data_base64: string;
      reply_to_message_id?: string | null;
      duration_secs?: number | null;
    },
  ) =>
    call<UploadAttachmentResponse>(
      "POST",
      `/conversations/${encodeURIComponent(conversationId)}/attachments`,
      { file_name: null, mime_type: null, reply_to_message_id: null, duration_secs: null, ...req },
    ),
  downloadAttachment: (contentHash: string) =>
    call<DownloadAttachmentResponse>("GET", `/attachments/${encodeURIComponent(contentHash)}/download`),
  deleteAttachment: (contentHash: string) =>
    call<void>("DELETE", `/attachments/${encodeURIComponent(contentHash)}`),

  // ---------------- calls (1:1, group, screen-share) ----------------
  startCall: (callId: string, video: boolean) =>
    call<CallSignalResponse>("POST", "/calls", { call_id: callId, video }),
  acceptCall: (offer: CallSignal) =>
    call<CallSignalResponse>("POST", "/calls/incoming", { offer }),
  completeCall: (callId: string, answer: CallSignal) =>
    call<void>("POST", `/calls/${encodeURIComponent(callId)}/complete`, { answer }),
  hangupCall: (callId: string) => call<void>("POST", `/calls/${encodeURIComponent(callId)}/hangup`),

  startCamera: (callId: string, fps?: number) =>
    call<void>("POST", `/calls/${encodeURIComponent(callId)}/camera/start`, { fps }),
  stopCamera: (callId: string) => call<void>("POST", `/calls/${encodeURIComponent(callId)}/camera/stop`),

  startScreenShare: (callId: string, fps?: number) =>
    call<void>("POST", `/calls/${encodeURIComponent(callId)}/screen-share/start`, { fps }),
  stopScreenShare: (callId: string) =>
    call<void>("POST", `/calls/${encodeURIComponent(callId)}/screen-share/stop`),

  startGroupCall: (callId: string, video: boolean, participantCount: number) =>
    call<GroupCallStartedResponse>("POST", "/calls/group/start", {
      call_id: callId,
      video,
      participant_count: participantCount,
    }),
  hangupGroupCall: (callId: string) =>
    call<void>("POST", `/calls/group/${encodeURIComponent(callId)}/hangup`),
};
