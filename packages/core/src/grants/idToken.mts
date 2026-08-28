/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { randomUUID } from "node:crypto";
import type { JWTPayload, KeyStore } from "../keys/KeyStore.mjs";
import type { UserSessionClaims } from "../user-sessions/types.mjs";
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
}

/**
 * Generates a signed id_token JWT (OIDC 1.0 Core §2).
 *
 * Claim composition:
 *   - iss = issuer
 *   - sub (required)
 *   - aud (required)
 *   - azp (optional, added when provided)
 *   - exp / iat (seconds since epoch)
 *   - auth_time (seconds since epoch, from `authTime`)
 *   - sid (session identifier for back-channel logout)
 *   - nonce (when provided by the authorize request)
 *   - scope-filtered user claims via {@link filterClaimsByScope}
 *
 * Header: `typ: "id+jwt"`. Not a hint: this value is **load-bearing**. The
 * logout endpoint's SF-1 check pins `id_token_hint` to exactly this `typ`
 * (`oauth/src/routes/logout.mts`), and every at+jwt-pinned surface (userinfo,
 * introspection, the central verifier) relies on it being disjoint from
 * RFC 9068's `at+jwt` to refuse an id_token presented as an access token.
 * The spelling is nonstandard — strict external RPs that validate `typ`
 * expect `JWT` or none (#293 item 9) — but changing it is a coordinated
 * migration (mint + logout pin + a dual-accept window for tokens already in
 * the wild), not an edit here.
 */
export async function generateIdToken(opts: GenerateIdTokenOptions): Promise<Token> {
	const now = Math.floor(Date.now() / 1000);
	const expiresIn = opts.expiresIn ?? 3600;
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
		...filterClaimsByScope(opts.userClaims, opts.scopes),
	};
	const token = await opts.keyStore.sign({ claims, header: { typ: "id+jwt" } });
	return {
		token,
		expiresIn,
		subject: opts.sub,
		audience: opts.aud,
		issuer: opts.issuer,
		// tokenType is intentionally omitted — id_token is not `at+jwt` / `rt+jwt`
	};
}
