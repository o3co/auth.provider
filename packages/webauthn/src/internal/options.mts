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
 * Internal WebAuthn options-generation helpers (spec §2.4).
 *
 * Thin wrappers around `@simplewebauthn/server`'s `generateRegistrationOptions`
 * and `generateAuthenticationOptions` that:
 *   1. Map `WebAuthnConfig` fields to SimpleWebAuthn's parameter shape.
 *   2. Encode `userId` as a Uint8Array via TextEncoder (WebAuthn §5.4.3 —
 *      user.id is an opaque byte sequence, no PII per spec §2.3.2).
 *   3. Enable discoverable-credentials flow when `allowCredentials` is empty
 *      (pass `undefined` instead of `[]` per SimpleWebAuthn convention).
 *   4. Map `attestationPreference = "indirect"` → `"none"` because
 *      SimpleWebAuthn v13.1.1 removed "indirect" from its server-side API
 *      (`attestationType` accepts only `'direct' | 'enterprise' | 'none'`).
 *   5. Set `authenticatorSelection.residentKey = "preferred"` to enable
 *      discoverable credentials by default (WebAuthn §2.4).
 *
 * NOT exported from the package barrel — internal use only.
 *
 * Cross-refs: Plan T26 / spec §2.4 / WebAuthn §5.4.3 / §2.3.2
 */

import type { WebAuthnCredential } from "@o3co/auth-provider-core";
import type {
	PublicKeyCredentialCreationOptionsJSON,
	PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/server";
import {
	generateAuthenticationOptions as swGenAuth,
	generateRegistrationOptions as swGenReg,
} from "@simplewebauthn/server";
import type { WebAuthnConfig } from "../config.mjs";

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

export async function generateRegistrationOptionsForUser(args: {
	readonly config: WebAuthnConfig;
	/** Opaque user handle per WebAuthn §5.4.3 / spec §2.3.2. No PII stored here. */
	readonly userId: string;
	readonly userName: string;
	readonly userDisplayName: string;
	readonly excludeCredentials: readonly WebAuthnCredential[];
	readonly challenge: Uint8Array;
}): Promise<PublicKeyCredentialCreationOptionsJSON> {
	// SimpleWebAuthn v13.1.1 removed "indirect" from attestationType.
	// Map "indirect" → "none" (least-privilege fallback).
	const attestationType =
		args.config.attestationPreference === "indirect"
			? ("none" as const)
			: args.config.attestationPreference;

	return swGenReg({
		rpName: args.config.rpName,
		rpID: args.config.rpId,
		// TextEncoder produces a Uint8Array from the opaque userId string.
		// SimpleWebAuthn accepts Uint8Array for userID and encodes it as base64url
		// in the returned PublicKeyCredentialCreationOptionsJSON.
		userID: new TextEncoder().encode(args.userId),
		userName: args.userName,
		userDisplayName: args.userDisplayName,
		attestationType,
		excludeCredentials: args.excludeCredentials.map((c) => ({
			id: c.credentialId,
			// Cast: SimpleWebAuthn expects AuthenticatorTransportFuture[]
			// (superset of our AuthenticatorTransport — adds "cable" and
			// "smart-card"). Our stored values are a strict subset; the cast
			// is safe since the common values round-trip without loss.
			// biome-ignore lint/suspicious/noExplicitAny: transport superset cast — see comment
			transports: c.transports as any,
		})),
		authenticatorSelection: {
			userVerification: args.config.userVerification,
			// residentKey: "preferred" enables discoverable credentials by default
			// per WebAuthn §2.4 / spec §2.4. Deployers needing strict passkey-only
			// enforcement may override to "required" via a future config field.
			residentKey: "preferred",
		},
		challenge: args.challenge,
	});
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

export async function generateAuthenticationOptionsForUser(args: {
	readonly config: WebAuthnConfig;
	/**
	 * Credentials the user has previously registered.
	 * Empty array → discoverable-credentials flow (pass undefined to SimpleWebAuthn
	 * so the client browser prompts the user to pick an available passkey).
	 */
	readonly allowCredentials: readonly WebAuthnCredential[];
	readonly challenge: Uint8Array;
}): Promise<PublicKeyCredentialRequestOptionsJSON> {
	return swGenAuth({
		rpID: args.config.rpId,
		userVerification: args.config.userVerification,
		// Empty array → discoverable flow: pass undefined so SimpleWebAuthn omits
		// allowCredentials from the JSON (rather than sending an empty list, which
		// some browsers interpret differently from absent).
		allowCredentials:
			args.allowCredentials.length === 0
				? undefined
				: args.allowCredentials.map((c) => ({
						id: c.credentialId,
						// biome-ignore lint/suspicious/noExplicitAny: transport superset cast — see comment on registration helper
						transports: c.transports as any,
					})),
		challenge: args.challenge,
	});
}
