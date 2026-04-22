/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
/**
 * OIDC-standard claim filter. Maps {@link UserSessionClaims} to the JWT-shaped
 * claim subset that the requested scopes authorize.
 *
 * Scope → claim mapping (strict whitelist):
 *   - profile  → name, picture
 *   - email    → email, email_verified (note the OIDC snake_case name)
 *   - groups   → groups (non-standard, opt-in per spec Section 6.4)
 *
 * `openid` scope itself yields no claim here — it governs whether id_token is
 * issued at all; `sub` is added by the caller (`generateIdToken`).
 *
 * Provider-specific claims (e.g. Google `hd`) are NEVER emitted — consumers
 * that need them must opt in via a custom scope mapping (out of scope for v1).
 */
export function filterClaimsByScope(claims, scopes) {
    const scopeSet = new Set(scopes);
    const out = {};
    if (scopeSet.has("profile")) {
        if (typeof claims.name === "string")
            out.name = claims.name;
        if (typeof claims.picture === "string")
            out.picture = claims.picture;
    }
    if (scopeSet.has("email")) {
        if (typeof claims.email === "string")
            out.email = claims.email;
        if (typeof claims.emailVerified === "boolean")
            out.email_verified = claims.emailVerified;
    }
    if (scopeSet.has("groups")) {
        // UserSessionClaims has an index signature allowing unknown custom fields;
        // filter to string members only so non-string elements (objects, numbers,
        // etc.) cannot leak into JWT/userinfo responses.
        if (Array.isArray(claims.groups)) {
            out.groups = claims.groups.filter((g) => typeof g === "string");
        }
    }
    return out;
}
