/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { randomUUID } from "node:crypto";
import type { JWTPayload, KeyStore } from "../keys/KeyStore.mjs";
import type { UserSessionClaims } from "../user-sessions/types.mjs";
import { authTimeAt, wellFormedAcr, wellFormedAmr } from "./authenticationClaims.mjs";
import { filterClaimsByScope } from "./claimFilter.mjs";
import type { Token } from "./token.mjs";

export interface GenerateIdTokenOptions {
	readonly sub: string;
	readonly aud: string;
	readonly azp?: string;
	readonly authTime: Date;
	readonly nonce?: string;
	readonly sid: string;
	readonly scopes: ReadonlyArray<string>;
	readonly userClaims: UserSessionClaims;
	readonly keyStore: KeyStore;
	readonly issuer: string;
	readonly expiresIn?: number; // default 3600 seconds
	/**
	 * Epoch seconds for `iat`, what `exp` is measured from, and the clock
	 * `authTime` is read against. The clock unless the caller supplies it.
	 */
	readonly issuedAt?: number;
	/**
	 * RFC 8176 authentication methods the session recorded; omitted when
	 * empty. `| undefined` because a session or code record may hold
	 * `undefined`, which a caller compiling with `exactOptionalPropertyTypes`
	 * must be able to pass on as it is.
	 */
	readonly amr?: readonly string[] | undefined;
	/** The Authentication Context Class Reference `/authorize` satisfied. See `amr` on `undefined`. */
	readonly acr?: string | undefined;
}

/**
 * Generates a signed id_token JWT (OIDC Core §2): iss, sub, aud, azp (when
 * given), exp, iat, jti, auth_time, sid (for back-channel logout), nonce
 * (when the authorize request sent one), well-formed amr / acr, and the user
 * claims the scopes authorize ({@link filterClaimsByScope}). `auth_time` is
 * `authTime` read against the instant that sets `iat` (`issuedAt`, else the
 * clock; `authTimeAt`), so never later than `iat`; one it cannot read — an
 * invalid `Date`, an instant before the epoch, one ahead of that instant by
 * more than `DEFAULT_CLOCK_SKEW_MS` — is a `RangeError`, and nothing is signed.
 * An `issuedAt` that is not whole, non-negative epoch seconds is refused too.
 *
 * Header `typ: "JWT"` is load-bearing: logout pins `id_token_hint` to it, and
 * every at+jwt-pinned surface (userinfo, introspection, the central verifier)
 * relies on it being **disjoint from RFC 9068's `at+jwt`** to refuse an
 * id_token presented as an access token. `JWT` also passes strict external
 * RPs that validate `typ`.
 */
export async function generateIdToken(opts: GenerateIdTokenOptions): Promise<Token> {
	const { issuedAt } = opts;
	// Whole epoch seconds, as `generateToken` takes it: anything else would sign
	// an `iat` / `exp` no verifier reads as intended.
	if (issuedAt !== undefined && !(Number.isSafeInteger(issuedAt) && issuedAt >= 0)) {
		throw new Error(
			"generateIdToken: issuedAt must be a non-negative whole number of epoch seconds",
		);
	}
	const nowMs = issuedAt === undefined ? Date.now() : issuedAt * 1000;
	// The id_token always carries `auth_time`: an instant it cannot read is refused, never signed.
	const authTime = authTimeAt(opts.authTime, nowMs);
	if (authTime === undefined) {
		throw new RangeError(
			"generateIdToken: authTime must be a valid instant at or after the epoch, no further ahead of the clock than DEFAULT_CLOCK_SKEW_MS",
		);
	}
	const now = issuedAt ?? Math.floor(nowMs / 1000);
	const expiresIn = opts.expiresIn ?? 3600;
	// A supplied `iat` can sit near 2^53, where `iat + expiresIn` rounds to a
	// neighbouring integer and two lifetimes would sign the same `exp`.
	if (issuedAt !== undefined && now + expiresIn > Number.MAX_SAFE_INTEGER) {
		throw new RangeError(
			`generateIdToken: exp (iat ${now} + expiresIn ${expiresIn}) is past Number.MAX_SAFE_INTEGER`,
		);
	}
	const amr = wellFormedAmr(opts.amr);
	const acr = wellFormedAcr(opts.acr);
	const claims: JWTPayload = {
		iss: opts.issuer,
		sub: opts.sub,
		aud: opts.aud,
		exp: now + expiresIn,
		iat: now,
		jti: randomUUID(),
		auth_time: authTime,
		sid: opts.sid,
		...(opts.azp ? { azp: opts.azp } : {}),
		...(opts.nonce ? { nonce: opts.nonce } : {}),
		...(amr ? { amr } : {}),
		...(acr ? { acr } : {}),
		...filterClaimsByScope(opts.userClaims, opts.scopes),
	};
	const token = await opts.keyStore.sign({ claims, header: { typ: "JWT" } });
	return {
		token,
		expiresIn,
		subject: opts.sub,
		audience: opts.aud,
		issuer: opts.issuer,
		// tokenType is intentionally omitted — id_token is not `at+jwt` / `rt+jwt`
	};
}
