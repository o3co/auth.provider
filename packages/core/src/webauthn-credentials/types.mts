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
 * SECURITY: `userId` is also the WebAuthn user handle (`user.id`) presented
 * to the authenticator, which persists it and may sync it across devices.
 * It MUST be opaque and MUST NOT contain PII (email, username, etc.), per
 * WebAuthn §5.4.3.
 */
export interface WebAuthnCredential {
	readonly userId: string;
	readonly credentialId: string;
	/**
	 * Authenticator public key in COSE format. **Logically immutable**:
	 * callers MUST NOT mutate the bytes, which would corrupt the store's view
	 * of the credential (TypeScript has no `ReadonlyUint8Array`).
	 *
	 * Deliberately the wide `Uint8Array<ArrayBufferLike>`, not
	 * `Uint8Array<ArrayBuffer>`: an adapter's natural source is its driver's
	 * `Buffer<ArrayBufferLike>` (possibly SharedArrayBuffer-backed), which the
	 * narrow form rejects at compile time. `@simplewebauthn/server` needs the
	 * narrow form, so `packages/webauthn/src/internal/verification.mts`
	 * copies the bytes at that call. Do not narrow it here: this port is
	 * implemented outside this repo.
	 */
	readonly publicKey: Uint8Array;
	readonly signCount: number;
	readonly transports?: ReadonlyArray<AuthenticatorTransport>;
	readonly backedUp: boolean;
	readonly createdAt: Date;
	readonly lastUsedAt?: Date;
	readonly nickname?: string;
}

/**
 * Storage contract for WebAuthn credential records. Implementations MUST be
 * safe to call concurrently; {@link updateSignCount} MUST be an atomic
 * compare-and-set, to close the replay window between concurrent verifies.
 * Domain failures throw {@link WebAuthnCredentialStorageError} (see
 * {@link registerCredential}).
 */
export interface WebAuthnCredentialStore {
	readonly kind: string;

	/**
	 * Atomically inserts a new credential record. Of N concurrent calls with
	 * one `credentialId`, exactly one MUST succeed.
	 *
	 * @throws WebAuthnCredentialStorageError `duplicate-credential` when the
	 *   `credentialId` already exists; the existing record MUST be left
	 *   unchanged.
	 */
	registerCredential(record: WebAuthnCredential): Promise<void>;

	/** Look up a credential by its credentialId. Returns null when not found. */
	findByCredentialId(credentialId: string): Promise<WebAuthnCredential | null>;

	/** Return all credentials registered for a given userId. */
	listByUserId(userId: string): Promise<readonly WebAuthnCredential[]>;

	/**
	 * Atomic compare-and-set: updates `signCount` and `lastUsedAt` only if the
	 * stored signCount equals `expectedCurrentSignCount` at the write.
	 *
	 * @returns `false` when it did not match (a concurrent update); callers
	 *   MUST treat that as a replay/clone attack signal. Also `false`, creating
	 *   nothing, for a `credentialId` it does not hold.
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
// The `declare module` block MUST name the package ("@o3co/auth-provider-core"),
// not a relative path, so consumer augmentations resolve to the same
// ComponentMap interface.
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		/** Optional WebAuthn credential store. Present when the webauthn package is wired. */
		readonly webauthnCredentialStore?: WebAuthnCredentialStore;
	}
}
