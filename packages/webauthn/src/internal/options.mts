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
 *   1. take `userId` as bytes, or a string they encode as UTF-8 (WebAuthn
 *      §5.4.3: `user.id` is an opaque byte sequence, no PII; README,
 *      "SECURITY — `userId` opacity");
 *   2. take credentials as descriptors, an id and its transports;
 *   3. pass `undefined` rather than `[]` for an empty `allowCredentials`, the
 *      discoverable-credentials flow;
 *   4. map `attestationPreference = "indirect"` to `"none"`, since
 *      SimpleWebAuthn's `attestationType` accepts only
 *      `'direct' | 'enterprise' | 'none'`;
 *   5. ask for the `authenticatorSelection.residentKey` the caller names;
 *   6. require an ArrayBuffer-backed `challenge` (see the field docs below).
 *
 * NOT exported from the package barrel, except `WEBAUTHN_ALGORITHM_IDS`,
 * which the barrel re-exports as the statement of the algorithm pin.
 */

import type { AuthenticatorTransport } from "@o3co/auth-provider-core";
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

/** A credential as the ceremony options name it: its id, and how a client may reach it when known. */
export interface WebAuthnCredentialDescriptor {
	readonly credentialId: string;
	readonly transports?: ReadonlyArray<AuthenticatorTransport>;
}

/** The descriptors as SimpleWebAuthn takes them. */
const descriptorsOf = (credentials: readonly WebAuthnCredentialDescriptor[]) =>
	credentials.map((c) => ({
		id: c.credentialId,
		// Cast: SimpleWebAuthn expects AuthenticatorTransportFuture[]
		// (superset of our AuthenticatorTransport — adds "cable" and
		// "smart-card"). Our stored values are a strict subset; the cast
		// is safe since the common values round-trip without loss.
		// biome-ignore lint/suspicious/noExplicitAny: transport superset cast — see comment
		transports: c.transports as any,
	}));

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

export async function generateRegistrationOptionsForUser(args: {
	readonly config: WebAuthnConfig;
	/**
	 * Opaque user handle per WebAuthn §5.4.3, 1 to 64 bytes. No PII stored here.
	 * Bytes are used as they are; a string is encoded as UTF-8.
	 */
	readonly userId: string | Uint8Array<ArrayBuffer>;
	readonly userName: string;
	readonly userDisplayName: string;
	readonly excludeCredentials: readonly WebAuthnCredentialDescriptor[];
	/**
	 * Whether the authenticator is asked to create a discoverable credential
	 * (WebAuthn Level 3 §5.4.6). Advisory: an authenticator may create one
	 * whatever is asked.
	 */
	readonly residentKey: "discouraged" | "preferred" | "required";
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
		// SimpleWebAuthn encodes userID as base64url in the returned
		// PublicKeyCredentialCreationOptionsJSON.
		userID: typeof args.userId === "string" ? new TextEncoder().encode(args.userId) : args.userId,
		userName: args.userName,
		userDisplayName: args.userDisplayName,
		attestationType,
		excludeCredentials: descriptorsOf(args.excludeCredentials),
		authenticatorSelection: {
			userVerification: args.config.userVerification,
			residentKey: args.residentKey,
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
	readonly allowCredentials: readonly WebAuthnCredentialDescriptor[];
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
			args.allowCredentials.length === 0 ? undefined : descriptorsOf(args.allowCredentials),
		challenge: args.challenge,
	});
}
