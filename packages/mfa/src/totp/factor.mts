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
 * The `totp` second factor (the MFA ADR's F6, D14, D21, D22), as core's
 * `MfaFactor` contract states it.
 *
 * - It adds `otp`, and `mfa` beside it; it counts as MFA; its proof, six to
 *   eight digits, is guessable, so the subject lock applies to it.
 * - A verification checks the factor the request named — no other of the
 *   subject's — under that factor's own algorithm, digits and period (F6: the
 *   parameters are stored per factor, so a configuration change never breaks
 *   an enrollment), at the configured window, and only at a step after the
 *   factor's `lastUsedStep`; it answers the step it matched as the factor's
 *   next data, which the coordinator writes by compare-and-set on the record's
 *   version. A code at or before `lastUsedStep` is `replayed`.
 * - A proof it cannot read — anything but a string of exactly the factor's
 *   number of ASCII digits — is `malformed`. Data or a pending state that is
 *   not a TOTP record is thrown, never answered as a wrong code: an unreadable
 *   factor is the coordinator's `503`, not the user's mistake (D11). What is
 *   thrown names the field and never quotes the secret.
 * - Enrollment — core's contract requires it of every factor — hands out a
 *   secret of the algorithm's output length (20, 32 or 64 bytes) in base32,
 *   and the `otpauth://` URI authenticator apps read, labelled
 *   `issuer:account` (the account's email, else its username); the pending
 *   state carries the parameters it was begun under, and completing binds the
 *   factor at the step its proof matched, so that code is spent.
 *
 * The factor holds no key, no store and no transaction: the coordinator opens
 * and seals what it is handed and returns (D7).
 */

import { randomBytes } from "node:crypto";
import {
	type MfaEnrollmentCompletion,
	type MfaFactor,
	type MfaFactorData,
	type MfaVerification,
	OTP_AMR,
} from "@o3co/auth-provider-core";
import { decodeBase32, encodeBase32 } from "./base32.mjs";
import {
	matchTotpCode,
	TOTP_ALGORITHMS,
	TOTP_DIGITS,
	TOTP_SECRET_BYTES,
	type TotpAlgorithm,
} from "./rfc6238.mjs";

/** The kind a TOTP factor's records carry, and the key it is contributed under. */
export const TOTP_FACTOR_KIND = "totp";

/** What the factor is built with: the parameters of a new enrollment, the window every verification allows, and the URI's issuer. */
export interface TotpFactorSettings {
	readonly algorithm: TotpAlgorithm;
	readonly digits: number;
	/** Seconds per step. */
	readonly period: number;
	/** Steps accepted either side of now. */
	readonly window: number;
	/** The `otpauth://` URI's issuer, and the first half of its label. */
	readonly issuer: string;
}

/** RFC 4226 §4, R6: a shared secret of at least 128 bits. */
const MIN_SECRET_BYTES = 16;

/** A factor's parameters, read: the secret decoded beside the spelling it is kept in. */
interface TotpParameters {
	readonly secret: string;
	readonly key: Buffer;
	readonly algorithm: TotpAlgorithm;
	readonly digits: number;
	readonly period: number;
}

/** A field of a TOTP record that is not what it must be. Names the field; quotes nothing. */
const unreadable = (what: string, field: string): Error =>
	new Error(`${what} is not a TOTP record: its ${field} cannot be read`);

/** The parameters a pending state or a factor's data carries, or a throw naming the field that is wrong. */
function readParameters(value: unknown, what: string): TotpParameters {
	const record = (typeof value === "object" && value !== null ? value : {}) as Record<
		string,
		unknown
	>;
	const { secret, algorithm, digits, period } = record;
	const key = typeof secret === "string" ? decodeBase32(secret) : undefined;
	if (key === undefined || key.length < MIN_SECRET_BYTES) throw unreadable(what, "secret");
	if (!TOTP_ALGORITHMS.includes(algorithm as TotpAlgorithm)) throw unreadable(what, "algorithm");
	if (
		typeof digits !== "number" ||
		!Number.isInteger(digits) ||
		digits < TOTP_DIGITS.min ||
		digits > TOTP_DIGITS.max
	) {
		throw unreadable(what, "digits");
	}
	if (typeof period !== "number" || !Number.isSafeInteger(period) || period <= 0) {
		throw unreadable(what, "period");
	}
	return { secret: secret as string, key, algorithm: algorithm as TotpAlgorithm, digits, period };
}

/** A factor's data: its parameters and the step its last accepted code was at. */
function readData(data: MfaFactorData): TotpParameters & { readonly lastUsedStep: number } {
	const what = "the factor's data";
	const parameters = readParameters(data, what);
	const { lastUsedStep } = data;
	if (typeof lastUsedStep !== "number" || !Number.isSafeInteger(lastUsedStep) || lastUsedStep < 0) {
		throw unreadable(what, "lastUsedStep");
	}
	return { ...parameters, lastUsedStep };
}

/** The proof as a code of `digits` ASCII digits, or `undefined` for anything else. */
function readCode(proof: unknown, digits: number): string | undefined {
	return typeof proof === "string" && proof.length === digits && /^[0-9]+$/.test(proof)
		? proof
		: undefined;
}

/** The label's account: the account's email, else its username — or a `RangeError` when it has neither. */
function accountOf(user: Readonly<Record<string, unknown>>): string {
	for (const candidate of [user.email, user.username]) {
		if (typeof candidate === "string" && candidate.length > 0) return candidate;
	}
	throw new RangeError(
		"a TOTP factor is labelled with the account's email or username; it has neither",
	);
}

/**
 * The Key URI authenticator apps and Apple's Passwords read (F6):
 * `otpauth://totp/<issuer>:<account>?secret=…&issuer=…&algorithm=…&digits=…&period=…`,
 * each name percent-encoded.
 */
function otpauthUri(
	issuer: string,
	account: string,
	parameters: Omit<TotpParameters, "key">,
): string {
	const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
	return (
		`otpauth://totp/${label}?secret=${parameters.secret}&issuer=${encodeURIComponent(issuer)}` +
		`&algorithm=${parameters.algorithm}&digits=${parameters.digits}&period=${parameters.period}`
	);
}

/** The `amr` values a verification adds; the same for every record (D14). */
const AMR: readonly string[] = Object.freeze([OTP_AMR]);

/** The `totp` factor, with `settings` for new enrollments and the window. */
export function createTotpFactor(settings: TotpFactorSettings): MfaFactor {
	const factor: MfaFactor = {
		kind: TOTP_FACTOR_KIND,
		amrValues: AMR,
		amrFor: () => AMR,
		addsMfa: true,
		counting: true,
		guessable: true,
		describe: () => ({}),

		async verify(ctx): Promise<MfaVerification> {
			const data = readData(ctx.factor.data);
			const code = readCode(ctx.proof, data.digits);
			if (code === undefined) return { ok: false, reason: "malformed" };
			const match = matchTotpCode(code, {
				secret: data.key,
				algorithm: data.algorithm,
				digits: data.digits,
				period: data.period,
				window: settings.window,
				nowMs: ctx.nowMs,
				lastUsedStep: data.lastUsedStep,
			});
			if (match.outcome === "matched") {
				return {
					ok: true,
					factorId: ctx.factor.id,
					next: { ...ctx.factor.data, lastUsedStep: match.step },
				};
			}
			return { ok: false, reason: match.outcome };
		},

		async beginEnrollment(ctx) {
			const account = accountOf(ctx.user);
			const { algorithm, digits, period } = settings;
			const secret = encodeBase32(randomBytes(TOTP_SECRET_BYTES[algorithm]));
			return {
				state: { secret, algorithm, digits, period },
				response: {
					secret,
					otpauth_uri: otpauthUri(settings.issuer, account, { secret, algorithm, digits, period }),
					algorithm,
					digits,
					period,
				},
			};
		},

		async completeEnrollment(ctx): Promise<MfaEnrollmentCompletion> {
			const { secret, key, algorithm, digits, period } = readParameters(
				ctx.state,
				"the pending enrollment",
			);
			const code = readCode(ctx.proof, digits);
			if (code === undefined) return { ok: false, reason: "malformed" };
			const match = matchTotpCode(code, {
				secret: key,
				algorithm,
				digits,
				period,
				window: settings.window,
				nowMs: ctx.nowMs,
			});
			if (match.outcome !== "matched") return { ok: false, reason: "invalid" };
			return {
				ok: true,
				data: { secret, algorithm, digits, period, lastUsedStep: match.step },
			};
		},
	};
	return Object.freeze(factor);
}
