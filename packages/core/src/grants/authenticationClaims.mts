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
 * The authentication claims a token may carry: `amr` (RFC 8176), `acr` and
 * `auth_time` (OIDC Core §2; on access tokens, RFC 9470 §6), read in one shape
 * by every grant that stamps them, plus the `amr` values this provider records
 * and `composeAmr`. See ADR 2026-09-25-multi-factor-authentication.
 *
 * They reach a token from a recorded `UserSession`, the code record, or an
 * earlier refresh token. A refresh copies them forward, vouching for them
 * again, so every grant reads them through the same predicates: no grant
 * stamps an `amr: []` the next one drops, and a resource server gating on
 * `amr` sees one answer per authentication.
 */

import { DEFAULT_CLOCK_SKEW_MS } from "../jwt/verify.mjs";

/** A password login (RFC 8176 `pwd`): what `POST /session/login` records. */
export const PASSWORD_AMR = "pwd";

/**
 * The marker a federated login records beside whatever the upstream IdP
 * asserted: "authenticated through a federation". RFC 8176 registers no value
 * for it and OIDC Core leaves `amr` values to the deployment, so it is
 * deployment-defined. In core because the MFA requirement rule reads it;
 * `@o3co/auth-provider-session` re-exports it.
 */
export const FEDERATED_AMR = "fed";

/**
 * RFC 8176 `mfa`: added once by the verification of a second factor that adds
 * it (`MfaFactor.addsMfa`), at a login, a step-up or a first binding alike.
 * What `urn:o3co:acr:mfa` requires.
 */
export const MFA_AMR = "mfa";

/** RFC 8176 `otp`: a one-time password from a device — a TOTP code. */
export const OTP_AMR = "otp";

/**
 * RFC 8176 `hwk`: proof of possession of a hardware-secured key — a WebAuthn
 * credential whose backup-state flag is clear, bound to one device.
 */
export const HARDWARE_KEY_AMR = "hwk";

/**
 * RFC 8176 `swk`: proof of possession of a software-secured key — a WebAuthn
 * credential that is backed up or synced, protected by the platform's sync
 * rather than one device's hardware.
 */
export const SOFTWARE_KEY_AMR = "swk";

/**
 * A one-time code mailed to the account's enrolled address. Deployment-defined,
 * as `fed` is: RFC 8176's `otp` would claim a one-time-password device. It
 * does not add `mfa` unless the email factor's own setting says so.
 */
export const EMAIL_OTP_AMR = "email";

/** A recovery code (a look-up secret). Deployment-defined; it adds `mfa`. */
export const RECOVERY_CODE_AMR = "recovery";

/**
 * `amr` as a token may carry it — a non-empty array of non-empty strings —
 * else undefined. Each element is read once, into the copy that is checked
 * and answered; a hole reads as `undefined` and fails.
 */
export function wellFormedAmr(value: unknown): readonly string[] | undefined {
	if (!Array.isArray(value)) return undefined;
	const copy: unknown[] = Array.from(value);
	if (copy.length === 0) return undefined;
	if (!copy.every((v) => typeof v === "string" && v.length > 0)) return undefined;
	return copy as string[];
}

/** `acr` as a token may carry it — a non-empty string — else undefined. */
export function wellFormedAcr(value: unknown): string | undefined {
	return typeof value === "string" && value.length > 0 ? value : undefined;
}

/** `auth_time` as a token may carry it — whole seconds since the epoch, not negative — else undefined. */
export function wellFormedAuthTime(value: unknown): number | undefined {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

/**
 * An authentication instant as `auth_time`: its whole seconds since the epoch, rounded down;
 * undefined for an invalid `Date` or an instant before the epoch. It does not read the instant
 * against a clock, so it does not cap one ahead of it; {@link authTimeAt} does.
 */
export function authTimeClaim(instant: Date): number | undefined {
	return wellFormedAuthTime(Math.floor(instant.getTime() / 1000));
}

/**
 * A recorded authentication instant as `auth_time`, read against the clock
 * `nowMs` that mints or judges with it: never later than that clock. An
 * instant up to `DEFAULT_CLOCK_SKEW_MS` ahead reads as `nowMs`; one further
 * ahead, a value that is not a valid `Date`, an instant before the epoch, or
 * a clock that is not a finite number, is undefined. Whole seconds, rounded
 * down. It never throws.
 */
export function authTimeAt(instant: unknown, nowMs: number): number | undefined {
	const instantMs = instant instanceof Date ? instant.getTime() : Number.NaN;
	if (!Number.isFinite(nowMs) || !(instantMs <= nowMs + DEFAULT_CLOCK_SKEW_MS)) return undefined;
	return wellFormedAuthTime(Math.floor(Math.min(instantMs, nowMs) / 1000));
}

/**
 * A session's `amr` after a second factor was verified in it: what it held,
 * then each value the factor adds that it did not hold, then `mfa` once when
 * the factor adds it. Insertion order, no repeats: a TOTP login is
 * `["pwd", "otp", "mfa"]`, a WebAuthn step-up on it appends `hwk`, an email
 * login is `["pwd", "email"]`.
 *
 * `mfa` comes from `addsMfa` alone. A factor value that is `mfa`, empty, not a
 * string, or a primary's marker (`pwd`, `fed`) is a `RangeError`: otherwise a
 * factor that does not add `mfa` could meet `urn:o3co:acr:mfa` by naming it,
 * or a second factor could change the baseline decided on the primary. `held`
 * is copied as it was, so compose onto `vouchedAmr(session)`, never a
 * session's raw `amr`. The input is never written through.
 */
export function composeAmr(
	held: readonly string[],
	verified: { readonly amr: readonly string[]; readonly addsMfa: boolean },
): readonly string[] {
	for (const value of verified.amr) {
		if (typeof value !== "string" || value.length === 0) {
			throw new RangeError("composeAmr: a factor's amr values must be non-empty strings");
		}
		if (value === MFA_AMR) {
			throw new RangeError(
				`composeAmr: a factor adds "${MFA_AMR}" through addsMfa, never among its own amr values`,
			);
		}
		if (value === PASSWORD_AMR || value === FEDERATED_AMR) {
			throw new RangeError(
				`composeAmr: "${value}" marks a primary authentication, never a second factor's amr`,
			);
		}
	}
	return [...new Set([...held, ...verified.amr, ...(verified.addsMfa ? [MFA_AMR] : [])])];
}
