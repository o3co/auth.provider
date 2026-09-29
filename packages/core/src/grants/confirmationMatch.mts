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
 */

/**
 * The ONE cnf/token-binding comparison matrix. Core owns the `Confirmation`
 * union (`grants/confirmation.mts`), so the matrix lives here with it.
 * Callers use {@link matchConfirmation} and keep only their own error
 * mapping: `invalid_grant` on the refresh grant, `invalid_request` on token
 * exchange (RFC 8693 §2.2.2), a 401 challenge at a protected resource,
 * `active: false` at introspection.
 */

import type { Confirmation } from "./confirmation.mjs";
import type { TokenBinding } from "./tokenBinding.mjs";

/**
 * Per-`cnf`-member binding profile: the mechanism `kind` that owns the
 * member, the auth scheme a token bound by it must be presented under, and
 * the `WWW-Authenticate` challenge naming that scheme. Core vocabulary, kept
 * with the `Confirmation` union rather than negotiated per mechanism package
 * (see ADR 2026-05-20-token-binding-first-class-abstraction).
 *
 * Matching gates on `kind`, not on the confirmation's shape alone:
 * `Confirmation` is mechanism-extensible, so a third-party mechanism could
 * emit `{ jkt }` without validating a DPoP proof and would otherwise be
 * handed a bound token.
 *
 * `cnf.jkt` REQUIRES the `DPoP` scheme (RFC 9449 §7.1: a DPoP-bound token
 * presented as Bearer is refused); `cnf["x5t#S256"]` keeps `Bearer`, since
 * RFC 8705 does not redefine the wire-level token type.
 */
export const BINDING_PROFILES = {
	jkt: { kind: "dpop", scheme: "dpop", challenge: "DPoP" },
	"x5t#S256": { kind: "mtls", scheme: "bearer", challenge: "Bearer" },
} as const satisfies Record<string, { kind: string; scheme: string; challenge: string }>;

/** A `cnf` member core recognizes as naming a binding. */
export type ConfirmationMember = keyof typeof BINDING_PROFILES;

export const CONFIRMATION_MEMBERS = Object.keys(BINDING_PROFILES) as readonly ConfirmationMember[];

/**
 * Read one member off a raw `cnf`-shaped value. Empty-string members are
 * rejected because RFC 9449 §6 / RFC 8705 §3 define both `jkt` (RFC 7638
 * JWK Thumbprint) and `x5t#S256` (DER cert SHA-256 thumbprint) as
 * non-empty base64url strings — a member that fails that is junk attached
 * to the object, not a binding.
 */
const readMember = (raw: unknown, member: ConfirmationMember): string | undefined => {
	if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
	const value = (raw as Record<string, unknown>)[member];
	return typeof value === "string" && value.length > 0 ? value : undefined;
};

/**
 * Outcome of comparing a token's raw `cnf` claim against the binding
 * presented on the current request.
 *
 * - `unbound`: the token names no binding. Callers that upgrade an unbound
 *   token to a bound one decide that from the presented binding.
 * - `compound`: more than one well-formed member. This AS mints one
 *   mechanism's confirmation per token, so this is a forged token or an AS
 *   bug; every surface refuses rather than picking a winner.
 * - `no-proof`: bound by `member`, but no binding of the owning kind
 *   presented it (stolen-token replay, or a mechanism removed while bound
 *   tokens are live).
 * - `mismatch`: the owning mechanism presented a different key or
 *   certificate.
 * - `satisfied`: the presented material matches the token's binding.
 */
export type ConfirmationMatch =
	| { readonly status: "unbound" }
	| { readonly status: "compound" }
	| { readonly status: "no-proof"; readonly member: ConfirmationMember; readonly expected: string }
	| { readonly status: "mismatch"; readonly member: ConfirmationMember; readonly expected: string }
	| { readonly status: "satisfied"; readonly member: ConfirmationMember; readonly value: string };

/**
 * Evaluate the sender-constraint matrix for one token: does the binding
 * presented on this request satisfy the token's `cnf` claim?
 *
 * `cnf` is the RAW claim off the JWT payload; validating its shape is this
 * function's job. `binding` is the request's resolved `TokenBinding`, if
 * any. Each member is compared only against a binding whose `kind` owns it
 * ({@link BINDING_PROFILES}), so a mechanism cannot satisfy a token bound by
 * another's proof.
 */
export const matchConfirmation = (
	cnf: unknown,
	binding: TokenBinding | null | undefined,
): ConfirmationMatch => {
	const present = CONFIRMATION_MEMBERS.filter((member) => readMember(cnf, member) !== undefined);
	if (present.length === 0) return { status: "unbound" };
	if (present.length > 1) return { status: "compound" };

	const member = present[0] as ConfirmationMember;
	const expected = readMember(cnf, member) as string;
	const presented =
		binding && binding.kind === BINDING_PROFILES[member].kind
			? readMember(binding.confirmation, member)
			: undefined;
	if (presented === undefined) return { status: "no-proof", member, expected };
	// Plain `!==` is fine: `jkt` is a thumbprint of a *public* key (RFC 7638)
	// and `x5t#S256` of a certificate sent openly in the TLS handshake
	// (RFC 8705 §3.1). Neither is secret, so timing leaks nothing the caller
	// lacks. (PKCE compares in constant time because its verifier IS secret.)
	if (presented !== expected) return { status: "mismatch", member, expected };
	return { status: "satisfied", member, value: expected };
};

/**
 * Narrow a presented binding's confirmation to the member its mechanism
 * `kind` owns, or `undefined` when the kind owns no recognized member (a
 * third-party mechanism) or the confirmation lacks it.
 *
 * What a grant stamps onto a token it issues: material the owning mechanism
 * validated, never `binding.confirmation` itself, which carries whatever a
 * mechanism returned.
 */
export const ownedConfirmation = (
	binding: TokenBinding | null | undefined,
): Confirmation | undefined => {
	if (!binding) return undefined;
	for (const member of CONFIRMATION_MEMBERS) {
		if (BINDING_PROFILES[member].kind !== binding.kind) continue;
		const value = readMember(binding.confirmation, member);
		if (value !== undefined) return { [member]: value } as Confirmation;
	}
	return undefined;
};

/**
 * Validate and narrow a raw `cnf` claim value into a `Confirmation`, or
 * `undefined` when it is not an object or carries no `jkt` / `x5t#S256`
 * member that is a non-empty string (RFC 9449 §6, RFC 8705 §3).
 *
 * A compound `cnf` narrows to `jkt`: DPoP wins over an ambient mTLS signal.
 * That is a claim-shape contract, NOT an admission decision. A caller that
 * vouches for a token to a third party (`/oauth/introspect`) MUST refuse a
 * compound one first ({@link isCompoundConfirmation}), or it would report a
 * binding the AS never issued. See ADR
 * 2026-05-20-token-binding-first-class-abstraction, "Compound cnf across the
 * AS surfaces".
 */
export const extractConfirmation = (raw: unknown): Confirmation | undefined => {
	for (const member of CONFIRMATION_MEMBERS) {
		const value = readMember(raw, member);
		if (value !== undefined) return { [member]: value } as Confirmation;
	}
	return undefined;
};

/**
 * The wire-level `token_type` for an access token with this `cnf` (the raw
 * claim, or the `Confirmation` a grant stamped): `DPoP` for `jkt` (RFC 9449
 * §5), `Bearer` for `x5t#S256` (RFC 8705 §3) or no binding. Read through
 * {@link extractConfirmation}, as every surface reads a `cnf`.
 *
 * Shared by the token response (`generateTokenResponse`) and introspection so
 * the two cannot disagree about the same token.
 */
export const tokenTypeForConfirmation = (cnf: unknown): "Bearer" | "DPoP" => {
	const confirmation = extractConfirmation(cnf);
	if (confirmation === undefined) return "Bearer";
	const member = CONFIRMATION_MEMBERS.find((candidate) => candidate in confirmation);
	return member === undefined ? "Bearer" : BINDING_PROFILES[member].challenge;
};

/**
 * Whether a raw `cnf` claim carries BOTH a well-formed `jkt` and a
 * well-formed `x5t#S256`. This AS never mints one, so it means a forged token
 * (signing-key compromise) or an AS bug: refuse the token rather than pick a
 * winner, as the refresh grant does with `invalid_grant`.
 *
 * Members are validated as in {@link extractConfirmation}: a second member
 * that is empty or not a string is junk beside a single binding, not compound.
 */
export const isCompoundConfirmation = (raw: unknown): boolean =>
	CONFIRMATION_MEMBERS.filter((member) => readMember(raw, member) !== undefined).length > 1;
