/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * Subset of W3C WebAuthn AuthenticatorTransport values supported by this
 * implementation. Maps to the CTAP/WebAuthn transport identifiers
 * (https://www.w3.org/TR/webauthn-2/#enumdef-authenticatortransport).
 */
export type AuthenticatorTransport = "ble" | "hybrid" | "internal" | "nfc" | "usb";

/**
 * WebAuthn credential record stored per registered passkey.
 *
 * SECURITY (§2.3.2): `userId` is ALSO used as the WebAuthn user-handle
 * (`user.id`) presented to the authenticator. It MUST be opaque and MUST NOT
 * contain PII (email, username, etc.) per WebAuthn §5.4.3. Authenticators
 * persist this value and may sync it across devices.
 */
export interface WebAuthnCredential {
	readonly userId: string;
	readonly credentialId: string;
	readonly publicKey: Uint8Array;
	readonly signCount: number;
	readonly transports?: ReadonlyArray<AuthenticatorTransport>;
	readonly backedUp: boolean;
	readonly createdAt: Date;
	readonly lastUsedAt?: Date;
	readonly nickname?: string;
}

/**
 * Storage contract for WebAuthn credential records (spec §2.3.1).
 *
 * Implementations MUST be safe to call concurrently. The {@link updateSignCount}
 * method is the critical path — it MUST be an atomic compare-and-set (CAS) to
 * prevent replay-window races between concurrent verify calls.
 *
 * Throws {@link WebAuthnCredentialStorageError} with the appropriate `reason`
 * discriminator on domain-level failures (see {@link registerCredential}).
 */
export interface WebAuthnCredentialStore {
	readonly kind: string;

	/**
	 * Atomically insert a new credential record.
	 *
	 * MUST throw `WebAuthnCredentialStorageError({ reason: "duplicate-credential" })`
	 * if a record with the same `credentialId` already exists. The existing
	 * record MUST be preserved unchanged — no partial mutation on failure.
	 *
	 * Concurrency contract: N concurrent calls with the same `credentialId`
	 * MUST result in exactly one success and N-1 throws of
	 * `WebAuthnCredentialStorageError({ reason: "duplicate-credential" })`.
	 *
	 * Per spec §2.3.1 + Codex Round 5 P2 (TOCTOU fix).
	 */
	registerCredential(record: WebAuthnCredential): Promise<void>;

	/** Look up a credential by its credentialId. Returns null when not found. */
	findByCredentialId(credentialId: string): Promise<WebAuthnCredential | null>;

	/** Return all credentials registered for a given userId. */
	listByUserId(userId: string): Promise<readonly WebAuthnCredential[]>;

	/**
	 * Atomic compare-and-set for signCount (spec §2.3.1, Codex fix #4).
	 *
	 * Updates `signCount` and `lastUsedAt` IFF the stored signCount equals
	 * `expectedCurrentSignCount` at the moment of the write.
	 *
	 * @returns `true` if the CAS succeeded; `false` if the stored signCount
	 *   did not match `expectedCurrentSignCount` (concurrent update race).
	 *   Callers MUST treat `false` as a replay/clone attack signal.
	 */
	updateSignCount(
		credentialId: string,
		args: {
			readonly expectedCurrentSignCount: number;
			readonly newSignCount: number;
			readonly lastUsedAt: Date;
		},
	): Promise<boolean>;

	/** Remove a credential by its credentialId. No-op if not found. */
	remove(credentialId: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge
// ---------------------------------------------------------------------------
// Per A1 §5.5 comment in challenges/types.mts: the `declare module` block
// MUST use the PACKAGE NAME ("@o3co/auth-provider-core"), NOT a relative path,
// so consumer augmentations resolve to the same ComponentMap interface.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		/** Optional WebAuthn credential store. Present when the webauthn package is wired. */
		readonly webauthnCredentialStore?: WebAuthnCredentialStore;
	}
}
