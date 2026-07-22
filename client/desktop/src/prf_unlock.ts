// Real database-unlock gate (THREAT_MODEL.md §3.7) via WebAuthn's PRF
// extension — see `src-tauri/src/prf_unlock.rs`'s module doc for why PRF
// specifically (a secret derived by the authenticator's own hardware,
// not extractable from OS-level storage) is the only sound mechanism for
// this, and why TOTP was ruled out (a TOTP secret has to sit in the clear
// somewhere the client can read it without the database open, making it
// exactly as exposed as the key it would protect).
//
// The derived PRF secret never leaves this machine and is never sent to
// the daemon over any channel other than as `BLACKHOLE_DB_PIN` — a local
// environment variable for a local child process — reusing the existing
// `bh-storage::db_key_lock` PIN mechanism (`POST /security/db-pin`)
// exactly as if the user had typed a (very long, random) PIN themselves.

import { invoke } from "@tauri-apps/api/core";

export interface PrfUnlockConfig {
  credential_id_b64url: string;
  rp_id: string;
}

export async function getPrfUnlockConfig(): Promise<PrfUnlockConfig | null> {
  return invoke<PrfUnlockConfig | null>("get_prf_unlock_config");
}

async function savePrfUnlockConfig(config: PrfUnlockConfig): Promise<void> {
  await invoke("save_prf_unlock_config", { config });
}

export async function clearPrfUnlockConfig(): Promise<void> {
  await invoke("clear_prf_unlock_config");
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function base64urlToBuffer(value: string): ArrayBuffer {
  const padded = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
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

// Fixed, application-specific PRF eval salt: every derivation for this one
// purpose uses the same salt, so the same physical credential always
// yields the same secret (PRF outputs are deterministic per
// credential+salt, per the WebAuthn Level 3 spec) — this is what makes it
// usable as a stable key-wrapping secret rather than a one-time nonce.
let cachedSalt: ArrayBuffer | null = null;
async function prfSalt(): Promise<ArrayBuffer> {
  if (cachedSalt) return cachedSalt;
  const bytes = new TextEncoder().encode("blackhole-db-unlock-prf-v1");
  cachedSalt = await crypto.subtle.digest("SHA-256", bytes);
  return cachedSalt;
}

/**
 * Requests a PRF assertion against `config`'s credential. Returns `null`
 * (never throws for this specific reason) if the authenticator/browser
 * didn't return a PRF result — e.g. an authenticator without `hmac-secret`
 * support, or a browser that doesn't implement the extension yet. Callers
 * should show that as "your authenticator doesn't support this," not a
 * generic error.
 */
export async function derivePrfSecret(config: PrfUnlockConfig): Promise<Uint8Array | null> {
  const salt = await prfSalt();
  const options: CredentialRequestOptions = {
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: config.rp_id,
      allowCredentials: [
        {
          id: base64urlToBuffer(config.credential_id_b64url),
          type: "public-key",
        },
      ],
      userVerification: "required",
      extensions: {
        prf: { eval: { first: salt } },
      },
      // The `prf` extension isn't in TypeScript's DOM lib types yet.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any,
  };

  const assertion = (await navigator.credentials.get(options)) as PublicKeyCredential;
  const extensionResults = assertion.getClientExtensionResults() as {
    prf?: { results?: { first?: ArrayBuffer } };
  };
  const first = extensionResults.prf?.results?.first;
  if (!first) return null;
  return new Uint8Array(first);
}

/**
 * Enrolls a *new* passkey credential dedicated to the database-unlock
 * gate (separate from `main.ts`'s existing UI-only local-unlock passkey,
 * which has no need for PRF) and immediately derives its secret. Two
 * user-visible authenticator touches happen here (create, then get) —
 * browsers only reliably return a usable PRF value from a `get()` call,
 * even though `create()` can request the extension to check support.
 * Throws if the authenticator doesn't support PRF; callers should catch
 * that and point the user at the manual-PIN flow instead.
 */
export async function enrollDatabaseUnlockGate(rpId: string): Promise<Uint8Array> {
  const createOptions: CredentialCreationOptions = {
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { id: rpId, name: "Blackhole" },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: "blackhole-db-unlock",
        displayName: "Blackhole database unlock",
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: { userVerification: "required" },
      extensions: { prf: {} },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any,
  };
  const created = (await navigator.credentials.create(createOptions)) as PublicKeyCredential;
  const extensionResults = created.getClientExtensionResults() as {
    prf?: { enabled?: boolean };
  };
  if (extensionResults.prf?.enabled !== true) {
    throw new Error(
      "This authenticator or browser doesn't support the PRF extension needed for a real " +
        "database lock. Use the manual PIN instead (Settings → Security).",
    );
  }

  const config: PrfUnlockConfig = {
    credential_id_b64url: bufferToBase64url(created.rawId),
    rp_id: rpId,
  };
  const secret = await derivePrfSecret(config);
  if (!secret) {
    throw new Error("The passkey did not return a PRF result right after enrollment.");
  }
  await savePrfUnlockConfig(config);
  return secret;
}
