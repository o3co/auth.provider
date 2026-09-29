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
 * Internal WebAuthn options-generation helpers: thin wrappers around
 * `@simplewebauthn/server`'s `generateRegistrationOptions` and
 * `generateAuthenticationOptions` that
 *   1. encode `userId` as bytes (WebAuthn §5.4.3: `user.id` is an opaque byte
 *      sequence, no PII; README, "SECURITY — `userId` opacity");
 *   2. pass `undefined` rather than `[]` for an empty `allowCredentials`, the
 *      discoverable-credentials flow;
 *   3. map `attestationPreference = "indirect"` to `"none"`, since
 *      SimpleWebAuthn's `attestationType` accepts only
 *      `'direct' | 'enterprise' | 'none'`;
 *   4. set `authenticatorSelection.residentKey = "preferred"`;
 *   5. require an ArrayBuffer-backed `challenge` (see the field docs below).
 *
 * NOT exported from the package barrel, except `WEBAUTHN_ALGORITHM_IDS`,
 * which the barrel re-exports as the statement of the algorithm pin.
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

/**
 * The public-key algorithms this provider offers at registration and accepts
 * at verification: EdDSA (-8), ES256 (-7), RS256 (-257), most preferred
 * first (README, "Dependency: SimpleWebAuthn").
 *
 * Stated here rather than left to `@simplewebauthn/server`, whose default is
 * a mutable module-level array it prepends ML-DSA-44 to whenever the runtime
 * reports support: what an authenticator is offered would depend on the Node
 * build, and a credential registered under an algorithm one deployment can
 * verify may reach another that cannot. A credential outlives the process
 * that registered it, so the set is a decision, not a default.
 *
 * Frozen, and exported on the barrel. The design vocabulary guards this as
 * the one definition (a second literal `supportedAlgorithmIDs` fails CI). A
 * registration outside the set is refused as `algorithm_not_allowed`.
 */
export const WEBAUTHN_ALGORITHM_IDS: readonly number[] = Object.freeze([-8, -7, -257]);

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

export async function generateRegistrationOptionsForUser(args: {
	readonly config: WebAuthnConfig;
	/** Opaque user handle per WebAuthn §5.4.3. No PII stored here. */
	readonly userId: string;
	readonly userName: string;
	readonly userDisplayName: string;
	readonly excludeCredentials: readonly WebAuthnCredential[];
	/**
	 * Ceremony challenge, ArrayBuffer-backed: `@simplewebauthn/server` requires
	 * the non-shared form, and a bare `Uint8Array` (`Uint8Array<ArrayBufferLike>`)
	 * admits a SharedArrayBuffer backing. Both callers build it with
	 * `crypto.getRandomValues(new Uint8Array(32))`, which has exactly this type.
	 */
	readonly challenge: Uint8Array<ArrayBuffer>;
}): Promise<PublicKeyCredentialCreationOptionsJSON> {
	// SimpleWebAuthn's attestationType has no "indirect": map it to "none"
	// (least-privilege fallback).
	const attestationType =
		args.config.attestationPreference === "indirect"
			? ("none" as const)
			: args.config.attestationPreference;

	return swGenReg({
		rpName: args.config.rpName,
		rpID: args.config.rpId,
		// This package's set, not the library's shifting default.
		supportedAlgorithmIDs: [...WEBAUTHN_ALGORITHM_IDS],
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
			// per WebAuthn §2.4.
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
	/** Ceremony challenge, ArrayBuffer-backed, as for registration. */
	readonly challenge: Uint8Array<ArrayBuffer>;
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
