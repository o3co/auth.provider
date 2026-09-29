/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { randomUUID } from "node:crypto";
import type { JWTPayload, KeyStore } from "../keys/KeyStore.mjs";
import type { UserSessionClaims } from "../user-sessions/types.mjs";
import { wellFormedAcr, wellFormedAmr } from "./authenticationClaims.mjs";
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
 * claims the scopes authorize ({@link filterClaimsByScope}).
 *
 * Header `typ: "JWT"` is load-bearing: logout pins `id_token_hint` to it, and
 * every at+jwt-pinned surface (userinfo, introspection, the central verifier)
 * relies on it being **disjoint from RFC 9068's `at+jwt`** to refuse an
 * id_token presented as an access token. `JWT` also passes strict external
 * RPs that validate `typ`.
 */
export async function generateIdToken(opts: GenerateIdTokenOptions): Promise<Token> {
	const now = Math.floor(Date.now() / 1000);
	const expiresIn = opts.expiresIn ?? 3600;
	const amr = wellFormedAmr(opts.amr);
	const acr = wellFormedAcr(opts.acr);
	const claims: JWTPayload = {
		iss: opts.issuer,
		sub: opts.sub,
		aud: opts.aud,
		exp: now + expiresIn,
		iat: now,
		jti: randomUUID(),
		auth_time: Math.floor(opts.authTime.getTime() / 1000),
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
