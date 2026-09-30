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
 * The doubles a second factor's tests use: `createTestMfaFactor`, a factor
 * with a trivial protocol, with or without a challenge, or mailing its codes; `testMfaFactorProofs`,
 * the proofs it takes; and `createTestMfaDigests`, keyed digests under a fixed
 * test key, as the coordinator hands a factor under the key ring. The
 * conformance suite a factor runs, `mfaFactorContract`, is
 * `@o3co/auth-provider-test-kit`'s. Published on
 * `@o3co/auth-provider-core/testing`.
 */

import { createHmac, randomBytes } from "node:crypto";
import { OTP_AMR } from "../grants/authenticationClaims.mjs";
import { normaliseMailAddress } from "../mail/address.mjs";
import type {
	MfaDigestMatch,
	MfaDigests,
	MfaEnrolledFactor,
	MfaFactor,
	MfaKeyedDigest,
} from "../mfa/factor.mjs";
import { constantTimeStringEqual } from "../security/timingSafe.mjs";

/** What the start of an enrollment answers. */
type EnrollmentStart = Awaited<ReturnType<MfaFactor["beginEnrollment"]>>;

/** What a challenge answers. */
type Challenge = Awaited<ReturnType<NonNullable<MfaFactor["challenge"]>>>;

// ---------------------------------------------------------------------------
// The digests a factor's tests hand it
// ---------------------------------------------------------------------------

/** The one key the test digests are made under, by id. */
const TEST_DIGEST_KEY_ID = "test-key";
const TEST_DIGEST_KEY = Buffer.from("o3co:mfa:test-digests-key:000000", "utf8");

/** `parts` bound to `kind`, each length-prefixed, so no part can move into its neighbour. */
function framed(kind: string, parts: readonly string[]): Buffer {
	return Buffer.concat(
		[kind, ...parts].flatMap((part) => {
			const bytes = Buffer.from(part, "utf8");
			const length = Buffer.alloc(4);
			length.writeUInt32BE(bytes.length);
			return [length, bytes];
		}),
	);
}

/**
 * Keyed digests for a factor of `kind` under one fixed test key, as the
 * coordinator makes them under the ring: HMAC-SHA-256 over the kind and the
 * parts, each length-prefixed, compared in constant time; a digest naming
 * another key is `key_unavailable`. For tests only: the key is public.
 */
export function createTestMfaDigests(kind: string): MfaDigests {
	const digestOf = (parts: readonly string[]): string =>
		createHmac("sha256", TEST_DIGEST_KEY).update(framed(kind, parts)).digest("base64url");
	return {
		digest: (parts): MfaKeyedDigest => ({ keyId: TEST_DIGEST_KEY_ID, digest: digestOf(parts) }),
		matchesDigest: (parts, stored): MfaDigestMatch => {
			if (stored.keyId !== TEST_DIGEST_KEY_ID) return "key_unavailable";
			return constantTimeStringEqual(digestOf(parts), stored.digest) ? "match" : "mismatch";
		},
	};
}

// ---------------------------------------------------------------------------
// The factor double
// ---------------------------------------------------------------------------

export interface TestMfaFactorOptions {
	/** Default `test`. */
	readonly kind?: string;
	/** Default `["otp"]`; `amrFor` answers them all. */
	readonly amrValues?: readonly string[];
	/** Default true. */
	readonly addsMfa?: boolean;
	/** Default true. */
	readonly counting?: boolean;
	/** Default false. */
	readonly guessable?: boolean;
	/**
	 * Answer a challenge before each verification: a nonce, kept as the
	 * challenge's state and answered to the page, which the verification must
	 * repeat beside the secret — as a WebAuthn assertion signs the challenge
	 * it was handed. Absent: there is no challenge.
	 */
	readonly challenge?: boolean;
	/**
	 * Mail codes instead, and take precedence over `challenge`: the enrollment
	 * asks for its code to be mailed (`email_factor_enrollment`) and each
	 * challenge for another (`login_code`), each expiring ten minutes on, which
	 * a verification repeats; the latest stands across attempts. Enrollable
	 * only by an account with an address. It keeps that address's keyed
	 * digest, never the address, and mails it with each login code.
	 */
	readonly mail?: boolean;
}

/** How long a code the double mails is accepted. */
const MAILED_CODE_TTL_MS = 600_000;

/**
 * A second factor with a trivial protocol, for tests: the enrollment answers
 * a random secret, and a verification is that secret — with `challenge`, the
 * secret and the nonce the latest challenge answered, as `secret:nonce`;
 * with `mail`, the code the latest challenge asked to be mailed.
 * {@link testMfaFactorProofs} makes the proofs. A proof that is not a string
 * is `malformed`.
 */
export function createTestMfaFactor(options: TestMfaFactorOptions = {}): MfaFactor {
	const amrValues = Object.freeze([...(options.amrValues ?? [OTP_AMR])]);
	const newSecret = (): string => randomBytes(8).toString("hex");
	const mails = options.mail === true;
	const factor: MfaFactor = {
		kind: options.kind ?? "test",
		amrValues,
		amrFor: () => amrValues,
		addsMfa: options.addsMfa ?? true,
		counting: options.counting ?? true,
		guessable: options.guessable ?? false,
		describe: () => ({}),
		beginEnrollment: async (ctx) => {
			const secret = newSecret();
			return mails
				? {
						state: { secret },
						response: { sent: true },
						mail: {
							purpose: "email_factor_enrollment",
							code: secret,
							expiresAtMs: ctx.nowMs + MAILED_CODE_TTL_MS,
						},
					}
				: { state: { secret }, response: { secret } };
		},
		completeEnrollment: async (ctx) => {
			if (typeof ctx.proof !== "string") return { ok: false, reason: "malformed" };
			if (ctx.proof !== ctx.state.secret) return { ok: false, reason: "invalid" };
			if (!mails) return { ok: true, data: { secret: ctx.state.secret } };
			const address = normaliseMailAddress(ctx.user.email);
			if (address === undefined) return { ok: false, reason: "invalid" };
			return { ok: true, data: { addressDigest: ctx.digests.digest([address]) } };
		},
		verify: async (ctx) => {
			if (typeof ctx.proof !== "string") return { ok: false, reason: "malformed" };
			if (mails) {
				const code = ctx.state?.code;
				if (typeof code !== "string") return { ok: false, reason: "expired" };
				if (ctx.proof !== code) return { ok: false, reason: "invalid" };
				const recorded = ctx.factor.data.addressDigest as MfaKeyedDigest | undefined;
				// A digest re-made under the ring's first key replaces one under another.
				return ctx.addressDigest !== undefined && ctx.addressDigest.keyId !== recorded?.keyId
					? { ok: true, factorId: ctx.factor.id, next: { addressDigest: ctx.addressDigest } }
					: { ok: true, factorId: ctx.factor.id };
			}
			const { secret } = ctx.factor.data;
			if (options.challenge !== true) {
				return ctx.proof === secret
					? { ok: true, factorId: ctx.factor.id }
					: { ok: false, reason: "invalid" };
			}
			const nonce = ctx.state?.nonce;
			if (typeof nonce !== "string") return { ok: false, reason: "expired" };
			return ctx.proof === `${String(secret)}:${nonce}`
				? { ok: true, factorId: ctx.factor.id }
				: { ok: false, reason: "invalid" };
		},
		...(mails
			? {
					reusableChallenge: true,
					enrollable: (user: Readonly<Record<string, unknown>>) =>
						typeof user.email === "string" && user.email !== "",
					challenge: async (ctx) => {
						const code = newSecret();
						return {
							state: { code },
							response: { sent: true },
							mail: {
								purpose: "login_code",
								code,
								expiresAtMs: ctx.nowMs + MAILED_CODE_TTL_MS,
								addressDigest: ctx.factor.data.addressDigest as MfaKeyedDigest,
							},
						};
					},
				}
			: options.challenge === true
				? {
						challenge: async () => {
							const nonce = newSecret();
							return { state: { nonce }, response: { nonce } };
						},
					}
				: {}),
	};
	return factor;
}

/**
 * The proofs of {@link createTestMfaFactor}: the secret its enrollment
 * answered, or the code it asked to be mailed; for a verification, that
 * secret — and, after a challenge, the nonce it answered, as `secret:nonce`
 * — or the code the challenge asked to be mailed. An input to the test
 * kit's `mfaFactorContract` beside the double.
 */
export const testMfaFactorProofs: {
	readonly enrollmentProof: (start: EnrollmentStart) => unknown;
	readonly verificationProof: (
		enrolled: MfaEnrolledFactor,
		challenge: Challenge | undefined,
	) => unknown;
} = Object.freeze({
	enrollmentProof: (start: EnrollmentStart) =>
		start.mail?.code ?? (start.response as { secret?: unknown }).secret,
	verificationProof: (enrolled: MfaEnrolledFactor, challenge: Challenge | undefined) => {
		if (challenge === undefined) return enrolled.data.secret;
		if (challenge.mail !== undefined) return challenge.mail.code;
		return `${String(enrolled.data.secret)}:${String((challenge.response as { nonce?: unknown }).nonce)}`;
	},
});
