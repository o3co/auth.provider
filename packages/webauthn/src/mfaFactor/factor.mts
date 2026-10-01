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
 * The `webauthn` second factor, as core's `MfaFactor` contract states it (the
 * MFA ADR's D4, D14, F7). See README, "WebAuthn as a second factor".
 *
 * - Registration asks for a credential under the subject's WebAuthn user
 *   handle — 32 random bytes made at its first WebAuthn enrollment and kept
 *   in each such factor's data — and named by its username, never its
 *   address, excluding the subject's WebAuthn
 *   credentials, with a resident key discouraged, no attestation,
 *   `WEBAUTHN_ALGORITHM_IDS` and the section's user verification. Completion
 *   verifies the attestation, its top origin held to `webauthn.topOrigin` as
 *   an assertion's is, and keeps the credential's backup eligibility (BE); a
 *   credential id the subject holds is `duplicate`.
 * - A credential is only ever looked up among its own subject's factors, so
 *   one id held by two subjects is not refused. Any path that resolves an
 *   MFA credential by its id alone must refuse such a duplicate first.
 * - An assertion's challenge lists every WebAuthn factor of the subject.
 *   Verification finds the credential by its id among them and verifies the
 *   assertion against the challenge the coordinator took, and a user handle
 *   the response carries against the subject's (WebAuthn §7.2 step 6), once
 *   the signature verified: another is `invalid`. Its next data is
 *   the new sign count and the backup state (BS) the assertion reports. A
 *   counter that did not increase over the stored one — judged only once
 *   the signature verified — is `sign_count_regression`, naming the record
 *   id of the factor whose credential asserted; 0 against a stored
 *   0 is an authenticator that keeps no counter (WebAuthn §6.1.1), which
 *   passes and stays 0. An assertion reporting another backup eligibility
 *   than the one registered is `invalid` (BE is fixed at creation, WebAuthn
 *   §6.1.3).
 * - `hwk` for a credential that is not backup-eligible (BE = 0), `swk` for
 *   one that is, whatever its backup state (the MFA ADR's D14). With
 *   attestation `none` both flags are what the authenticator reports of
 *   itself: `hwk` means reported device-bound, not proven hardware. The
 *   backup state is kept for the record; no decision reads it.
 * - A record's identity is its credential id, read as the record's data is.
 *   Data the factor cannot read has none: the identity never throws.
 * - A ceremony's challenge lives until the relying party's
 *   `challengeTtlMs`; the transaction bounds it too.
 * - Data or a pending state that is not a WebAuthn record is thrown (the
 *   coordinator's 503), never answered as a wrong proof, and what is thrown
 *   quotes nothing. The factor holds no key, no store and no transaction.
 */

import { randomBytes } from "node:crypto";
import {
	type AuthenticatorTransport,
	HARDWARE_KEY_AMR,
	type MfaEnrolledFactor,
	type MfaEnrollmentCompletion,
	type MfaFactor,
	type MfaFactorData,
	type MfaVerification,
	SOFTWARE_KEY_AMR,
} from "@o3co/auth-provider-core";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import type { WebAuthnConfig } from "../config.mjs";
import {
	generateAuthenticationOptionsForUser,
	generateRegistrationOptionsForUser,
	type WebAuthnCredentialDescriptor,
} from "../internal/options.mjs";
import {
	verifyWebAuthnAssertionWithBackupState,
	verifyWebAuthnAttestationWithBackupState,
} from "../internal/verification.mjs";

/** The kind a WebAuthn factor's records carry, and the key it is contributed under. */
export const WEBAUTHN_MFA_FACTOR_KIND = "webauthn";

/** The user verification a ceremony asks for (WebAuthn §5.8.6). */
export type UserVerificationRequirement = "required" | "preferred" | "discouraged";

/** What the factor is built with. */
export interface WebAuthnMfaFactorSettings {
	/** The relying party the `webauthnConfig` slot holds: its id, name, origins and challenge lifetime. */
	readonly relyingParty: WebAuthnConfig;
	/** What every ceremony asks for, and a verification requires when `required`. */
	readonly userVerification: UserVerificationRequirement;
}

/** A WebAuthn factor's data: what an assertion is verified with, and the subject's user handle. */
interface WebAuthnFactorData {
	readonly credentialId: string;
	/** The COSE public key, base64url. */
	readonly publicKey: string;
	readonly signCount: number;
	readonly transports: readonly AuthenticatorTransport[];
	/** Whether the credential may be backed up (BE), as it registered: what `amr` follows. */
	readonly backupEligible: boolean;
	/** The backup state (BS) the credential last reported, kept for the record. */
	readonly backedUp: boolean;
	/** The subject's WebAuthn user handle, base64url. */
	readonly userHandle: string;
}

const TRANSPORTS: ReadonlySet<string> = new Set<AuthenticatorTransport>([
	"ble",
	"hybrid",
	"internal",
	"nfc",
	"usb",
]);

/** The bytes of the user handle a first WebAuthn enrollment makes. */
const USER_HANDLE_BYTES = 32;
/** WebAuthn §5.4.3: a user handle is at most 64 bytes. */
const MAX_USER_HANDLE_BYTES = 64;

const BASE64URL = /^[A-Za-z0-9_-]+$/;

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

const isBase64url = (value: unknown): value is string =>
	typeof value === "string" && BASE64URL.test(value);

const isCount = (value: unknown): value is number =>
	typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

/** A field of a WebAuthn record that is not what it must be. Names the field; quotes nothing. */
const unreadable = (what: string, field: string): Error =>
	new Error(`${what} is not a WebAuthn record: its ${field} cannot be read`);

/** A factor's data, or a throw naming the field that is wrong. */
function readData(data: unknown): WebAuthnFactorData {
	const what = "the factor's data";
	const record = isRecord(data) ? data : {};
	const { credentialId, publicKey, signCount, transports, backupEligible, backedUp, userHandle } =
		record;
	if (!isBase64url(credentialId)) throw unreadable(what, "credentialId");
	if (!isBase64url(publicKey)) throw unreadable(what, "publicKey");
	if (!isCount(signCount)) throw unreadable(what, "signCount");
	if (!Array.isArray(transports) || !transports.every((t) => typeof t === "string")) {
		throw unreadable(what, "transports");
	}
	if (typeof backupEligible !== "boolean") throw unreadable(what, "backupEligible");
	if (typeof backedUp !== "boolean") throw unreadable(what, "backedUp");
	return {
		credentialId,
		publicKey,
		signCount,
		transports: knownTransports(transports),
		backupEligible,
		backedUp,
		userHandle: readUserHandle(userHandle, what),
	};
}

/**
 * A stored user handle: canonical base64url of 1 to 64 bytes (WebAuthn §5.4.3), the only form
 * the factor writes, since the handle an assertion is held to is the bytes it decodes to.
 */
function readUserHandle(value: unknown, what: string): string {
	const handle = isBase64url(value) ? Buffer.from(value, "base64url") : Buffer.alloc(0);
	const canonical = handle.length > 0 && handle.toString("base64url") === value;
	if (!canonical || handle.length > MAX_USER_HANDLE_BYTES) throw unreadable(what, "userHandle");
	return value as string;
}

/** The factors among `factors` whose data reads, each with it. */
function readable(
	factors: readonly MfaEnrolledFactor[],
): { readonly factor: MfaEnrolledFactor; readonly data: WebAuthnFactorData }[] {
	return factors.flatMap((factor) => {
		try {
			return [{ factor, data: readData(factor.data) }];
		} catch {
			return [];
		}
	});
}

/** The transports WebAuthn defines that the provider knows, in the order given. */
const knownTransports = (transports: readonly unknown[]): AuthenticatorTransport[] =>
	transports.filter((t): t is AuthenticatorTransport => typeof t === "string" && TRANSPORTS.has(t));

const descriptorOf = (data: WebAuthnFactorData): WebAuthnCredentialDescriptor => ({
	credentialId: data.credentialId,
	transports: data.transports,
});

/** A pending ceremony's state: its challenge, and until when it may be answered. */
function readCeremony(
	state: unknown,
	what: string,
): { readonly challenge: string; readonly expiresAtMs: number } {
	const { challenge, expiresAtMs } = isRecord(state) ? state : {};
	if (!isBase64url(challenge)) throw unreadable(what, "challenge");
	if (typeof expiresAtMs !== "number" || !Number.isFinite(expiresAtMs)) {
		throw unreadable(what, "expiresAtMs");
	}
	return { challenge, expiresAtMs };
}

/** A pending enrollment's state: its ceremony, and the user handle the credential is made under. */
function readEnrollment(state: unknown): {
	readonly challenge: string;
	readonly expiresAtMs: number;
	readonly userHandle: string;
} {
	const what = "the pending enrollment";
	const ceremony = readCeremony(state, what);
	const { userHandle } = state as Readonly<Record<string, unknown>>;
	return { ...ceremony, userHandle: readUserHandle(userHandle, what) };
}

const isText = (value: unknown): value is string => typeof value === "string" && value.length > 0;

/** The proof as a registration response, its own fields only, or `undefined`. */
function readRegistration(proof: unknown): RegistrationResponseJSON | undefined {
	if (!isRecord(proof) || !isRecord(proof.response)) return undefined;
	const { id, rawId, type, response, clientExtensionResults, authenticatorAttachment } = proof;
	const { clientDataJSON, attestationObject, transports } = response as Record<string, unknown>;
	if (!isText(id) || !isText(rawId) || type !== "public-key") return undefined;
	if (!isText(clientDataJSON) || !isText(attestationObject)) return undefined;
	if (transports !== undefined && !(Array.isArray(transports) && transports.every(isText))) {
		return undefined;
	}
	return {
		id,
		rawId,
		type,
		response: {
			clientDataJSON,
			attestationObject,
			...(transports === undefined ? {} : { transports: transports as never }),
		},
		clientExtensionResults: isRecord(clientExtensionResults) ? clientExtensionResults : {},
		...(authenticatorAttachment === "platform" || authenticatorAttachment === "cross-platform"
			? { authenticatorAttachment }
			: {}),
	};
}

/** The proof as an assertion, its own fields only, or `undefined`. */
function readAssertion(proof: unknown): AuthenticationResponseJSON | undefined {
	if (!isRecord(proof) || !isRecord(proof.response)) return undefined;
	const { id, rawId, type, response, clientExtensionResults, authenticatorAttachment } = proof;
	const { clientDataJSON, authenticatorData, signature, userHandle } = response as Record<
		string,
		unknown
	>;
	if (!isText(id) || !isText(rawId) || type !== "public-key") return undefined;
	if (!isText(clientDataJSON) || !isText(authenticatorData) || !isText(signature)) {
		return undefined;
	}
	// A `null` user handle is none, as the WebAuthn JSON form writes an absent one.
	if (userHandle !== undefined && userHandle !== null && typeof userHandle !== "string") {
		return undefined;
	}
	return {
		id,
		rawId,
		type,
		response: {
			clientDataJSON,
			authenticatorData,
			signature,
			...(typeof userHandle === "string" ? { userHandle } : {}),
		},
		clientExtensionResults: isRecord(clientExtensionResults) ? clientExtensionResults : {},
		...(authenticatorAttachment === "platform" || authenticatorAttachment === "cross-platform"
			? { authenticatorAttachment }
			: {}),
	};
}

/**
 * The name the authenticator shows for the account: its username, never its
 * address, which the provider keeps none of and a page does not show. A
 * `RangeError`, quoting nothing, when it has none as well-formed text.
 */
function accountOf(user: Readonly<Record<string, unknown>>): string {
	const { username } = user;
	if (typeof username === "string" && username.length > 0 && username.isWellFormed()) {
		return username;
	}
	throw new RangeError(
		"a WebAuthn factor names the account by its username; it has none as well-formed text",
	);
}

/** 32 bytes from the CSPRNG, as the option builders take a challenge. */
const newChallenge = (): Uint8Array<ArrayBuffer> => crypto.getRandomValues(new Uint8Array(32));

/** `value`, base64url, as bytes the option builders take. */
const bytesOf = (value: string): Uint8Array<ArrayBuffer> =>
	new Uint8Array(Buffer.from(value, "base64url"));

const AMR_VALUES: readonly string[] = Object.freeze([HARDWARE_KEY_AMR, SOFTWARE_KEY_AMR]);
const HWK: readonly string[] = Object.freeze([HARDWARE_KEY_AMR]);
const SWK: readonly string[] = Object.freeze([SOFTWARE_KEY_AMR]);

/** The `webauthn` factor over `settings`. */
export function createWebAuthnMfaFactor(settings: WebAuthnMfaFactorSettings): MfaFactor {
	const { relyingParty, userVerification } = settings;
	// The relying party as this factor's ceremonies ask: no attestation, the section's user verification.
	const ceremony: WebAuthnConfig = {
		...relyingParty,
		attestationPreference: "none",
		userVerification,
	};
	const expiresAt = (nowMs: number): number => nowMs + relyingParty.challengeTtlMs;

	const factor: MfaFactor = {
		kind: WEBAUTHN_MFA_FACTOR_KIND,
		amrValues: AMR_VALUES,
		amrFor: (data) => (readData(data).backupEligible ? SWK : HWK),
		addsMfa: true,
		counting: true,
		guessable: false,
		describe: () => ({}),
		// The credential id, which an assertion leaves as it is. Never throws: data the factor
		// cannot read names none.
		identity: (data) => {
			try {
				return readData(data).credentialId;
			} catch {
				return undefined;
			}
		},

		async challenge(ctx) {
			readData(ctx.factor.data);
			const options = await generateAuthenticationOptionsForUser({
				config: ceremony,
				allowCredentials: readable(ctx.factors).map(({ data }) => descriptorOf(data)),
				challenge: newChallenge(),
			});
			return {
				state: { challenge: options.challenge, expiresAtMs: expiresAt(ctx.nowMs) },
				response: options,
			};
		},

		async verify(ctx): Promise<MfaVerification> {
			const assertion = readAssertion(ctx.proof);
			if (assertion === undefined) return { ok: false, reason: "malformed" };
			readData(ctx.factor.data);
			if (ctx.state === undefined) return { ok: false, reason: "expired" };
			const state = readCeremony(ctx.state, "the challenge's state");
			if (ctx.nowMs >= state.expiresAtMs) return { ok: false, reason: "expired" };
			const found = readable(ctx.factors).find(({ data }) => data.credentialId === assertion.id);
			if (found === undefined) return { ok: false, reason: "invalid" };
			const { data } = found;
			const verified = await verifyWebAuthnAssertionWithBackupState({
				credential: {
					credentialId: data.credentialId,
					publicKey: bytesOf(data.publicKey),
					signCount: data.signCount,
					transports: data.transports,
				},
				response: assertion,
				expectedChallenge: state.challenge,
				expectedRpId: relyingParty.rpId,
				expectedOrigins: relyingParty.origin,
				...(relyingParty.topOrigin === undefined
					? {}
					: { expectedTopOrigins: relyingParty.topOrigin }),
				userVerification,
				// WebAuthn §7.2 step 6: a user handle the response carries must be the subject's.
				expectedUserHandle: bytesOf(data.userHandle),
			});
			if (!verified.ok) {
				// Any other refusal, `user_handle_mismatch` included, is the contract's `invalid`.
				return verified.reason === "sign_count_regression"
					? { ok: false, reason: "sign_count_regression", factorId: found.factor.id }
					: { ok: false, reason: "invalid" };
			}
			// BE is fixed at creation (WebAuthn §6.1.3): another one is not this credential's word.
			if (verified.backupEligible !== data.backupEligible) return { ok: false, reason: "invalid" };
			const next: WebAuthnFactorData = {
				...data,
				signCount: verified.newSignCount,
				backedUp: verified.backedUp,
			};
			return { ok: true, factorId: found.factor.id, next: next as unknown as MfaFactorData };
		},

		async beginEnrollment(ctx) {
			const held = readable(ctx.factors).map(({ data }) => data);
			const userHandle =
				held[0]?.userHandle ?? randomBytes(USER_HANDLE_BYTES).toString("base64url");
			const account = accountOf(ctx.user);
			const options = await generateRegistrationOptionsForUser({
				config: ceremony,
				userId: bytesOf(userHandle),
				userName: account,
				userDisplayName: account,
				excludeCredentials: held.map(descriptorOf),
				// A second factor needs no discoverable credential; a synced
				// passkey may be one whatever is asked.
				residentKey: "discouraged",
				challenge: newChallenge(),
			});
			return {
				state: { challenge: options.challenge, userHandle, expiresAtMs: expiresAt(ctx.nowMs) },
				response: options,
			};
		},

		async completeEnrollment(ctx): Promise<MfaEnrollmentCompletion> {
			const registration = readRegistration(ctx.proof);
			if (registration === undefined) return { ok: false, reason: "malformed" };
			const state = readEnrollment(ctx.state);
			if (ctx.nowMs >= state.expiresAtMs) return { ok: false, reason: "expired" };
			const verified = await verifyWebAuthnAttestationWithBackupState({
				response: registration,
				expectedChallenge: state.challenge,
				expectedRpId: relyingParty.rpId,
				expectedOrigins: relyingParty.origin,
				...(relyingParty.topOrigin === undefined
					? {}
					: { expectedTopOrigins: relyingParty.topOrigin }),
				userVerification,
			});
			if (!verified.ok) return { ok: false, reason: "invalid" };
			const { material } = verified;
			if (readable(ctx.factors).some(({ data }) => data.credentialId === material.credentialId)) {
				return { ok: false, reason: "duplicate" };
			}
			const data: WebAuthnFactorData = {
				credentialId: material.credentialId,
				publicKey: Buffer.from(material.publicKey).toString("base64url"),
				signCount: material.signCount,
				transports: knownTransports(material.transports ?? []),
				backupEligible: material.backupEligible,
				backedUp: material.backedUp,
				userHandle: state.userHandle,
			};
			return { ok: true, data: data as unknown as MfaFactorData };
		},
	};
	return Object.freeze(factor);
}
