/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { randomUUID } from "node:crypto";
import { filterClaimsByScope } from "./claimFilter.mjs";
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
 * Header: `typ: "id+jwt"` (RFC 9068 is at+jwt; id_token is in the OIDC family but
 * we use typ for introspection convenience — the header is a hint, not spec-mandated).
 */
export async function generateIdToken(opts) {
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = opts.expiresIn ?? 3600;
    const claims = {
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
