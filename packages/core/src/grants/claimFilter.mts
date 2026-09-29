/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import type { UserSessionClaims } from "../user-sessions/types.mjs";

/**
 * OIDC-standard claim filter: the subset of {@link UserSessionClaims} the
 * requested scopes authorize, as JWT claims. A strict whitelist:
 *   - profile → name, picture
 *   - email   → email, email_verified
 *   - groups  → groups (non-standard, opt-in)
 *
 * `openid` yields no claim here; it governs whether an id_token is issued,
 * and the caller (`generateIdToken`) adds `sub`. Provider-specific claims
 * (e.g. Google `hd`) are never emitted.
 */
export function filterClaimsByScope(
	claims: UserSessionClaims,
	scopes: ReadonlyArray<string>,
): Record<string, unknown> {
	const scopeSet = new Set(scopes);
	const out: Record<string, unknown> = {};
	if (scopeSet.has("profile")) {
		if (typeof claims.name === "string") out.name = claims.name;
		if (typeof claims.picture === "string") out.picture = claims.picture;
	}
	if (scopeSet.has("email")) {
		if (typeof claims.email === "string") out.email = claims.email;
		if (typeof claims.emailVerified === "boolean") out.email_verified = claims.emailVerified;
	}
	if (scopeSet.has("groups")) {
		// UserSessionClaims has an index signature allowing unknown custom fields;
		// filter to string members only so non-string elements (objects, numbers,
		// etc.) cannot leak into JWT/userinfo responses.
		if (Array.isArray(claims.groups)) {
			out.groups = claims.groups.filter((g): g is string => typeof g === "string");
		}
	}
	return out;
}
