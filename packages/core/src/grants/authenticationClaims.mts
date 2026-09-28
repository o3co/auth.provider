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
 * The authentication claims a token may carry (#481): `amr` (RFC 8176) and
 * `acr` (OIDC Core §2), read in one shape by every grant that stamps them —
 * and the `amr` values this provider records, with the one function that
 * composes them (the MFA ADR's D13 and D14).
 *
 * They reach a token from a recorded `UserSession` (a password login, a
 * federation login recording the upstream IdP's `amr` as it arrived), from the
 * code record, or from a refresh token a previous grant minted. A refresh does
 * not repeat the authentication, so the claims are copied forward — and a claim
 * copied forward is a claim vouched for again. One predicate is what keeps a
 * grant from stamping an `amr: []` that the next grant drops, so a resource
 * server gating on `amr` sees one answer for one authentication.
 */

/** A password login (RFC 8176 `pwd`): what `POST /session/login` records. */
export const PASSWORD_AMR = "pwd";

/**
 * #481 — the marker a federated login records beside whatever the upstream
 * IdP asserted: "authenticated through a federation". RFC 8176 registers no
 * value for that, and OIDC Core leaves `amr` values to the deployment, so the
 * marker is documented rather than borrowed. Core's since the MFA ADR (D13),
 * because the requirement rule reads it; `@o3co/auth-provider-session`
 * re-exports it.
 */
export const FEDERATED_AMR = "fed";

/**
 * RFC 8176 `mfa`: added once by the verification of a second factor that adds
 * it (`MfaFactor.addsMfa`), at a login, a step-up or a first binding alike
 * (the MFA ADR's D14). What `urn:o3co:acr:mfa` requires.
 */
export const MFA_AMR = "mfa";

/** RFC 8176 `otp`: a one-time password from a device — a TOTP code (D14). */
export const OTP_AMR = "otp";

/**
 * RFC 8176 `hwk`: proof of possession of a hardware-secured key — a WebAuthn
 * credential whose backup-state flag is clear, bound to one device (D14).
 */
export const HARDWARE_KEY_AMR = "hwk";

/**
 * RFC 8176 `swk`: proof of possession of a software-secured key — a WebAuthn
 * credential that is backed up or synced, protected by the platform's sync
 * rather than one device's hardware (D14).
 */
export const SOFTWARE_KEY_AMR = "swk";

/**
 * A one-time code mailed to the account's enrolled address. Deployment-defined,
 * as `fed` is: RFC 8176's `otp` would claim a one-time-password device. It
 * does not add `mfa` unless `mfa.factors.email.addsMfa` says so (O7).
 */
export const EMAIL_OTP_AMR = "email";

/** A recovery code (a look-up secret). Deployment-defined; it adds `mfa` (D25). */
export const RECOVERY_CODE_AMR = "recovery";

/** `amr` as a token may carry it — a non-empty array of non-empty strings, copied — else undefined. */
export function wellFormedAmr(value: unknown): readonly string[] | undefined {
	if (!Array.isArray(value) || value.length === 0) return undefined;
	if (!value.every((v) => typeof v === "string" && v.length > 0)) return undefined;
	return [...(value as string[])];
}

/** `acr` as a token may carry it — a non-empty string — else undefined. */
export function wellFormedAcr(value: unknown): string | undefined {
	return typeof value === "string" && value.length > 0 ? value : undefined;
}

/**
 * A session's `amr` after a second factor was verified in it (the MFA ADR's
 * D14): what it held, then each value the factor adds that it did not hold,
 * then `mfa` once when the factor adds it. Order is insertion and no value
 * appears twice, so a TOTP login is `["pwd", "otp", "mfa"]`, a WebAuthn
 * step-up on it appends `hwk`, and an email login is `["pwd", "email"]`.
 *
 * `mfa` comes from `addsMfa` alone: a factor that lists it among its own
 * values is a `RangeError`, as is an empty or non-string value — otherwise a
 * factor that does not add `mfa` (the email code, by default) could meet
 * `urn:o3co:acr:mfa` by naming it. So is a factor that lists a primary's
 * marker, `pwd` or `fed`: the baseline is decided on the primary (D13), and a
 * second factor must not change it. What the session held is the record's
 * and is copied as it was, each value once — so a caller composes onto
 * `vouchedAmr(session)`, never onto an `amr` the D9 split has not been
 * applied to. The input is never written through.
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
