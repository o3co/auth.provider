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
import { BINDING_PROFILES } from "./grants/confirmationMatch.mjs";
/**
 * The auth schemes that carry an access token as the credential.
 *
 * `Bearer` is RFC 6750 §2.1. The rest are the per-binding presentation
 * schemes from `BINDING_PROFILES` — today only `DPoP` (RFC 9449 §7.1,
 * which requires a DPoP-bound access token to be presented under its own
 * scheme rather than as a Bearer token; that separation is what lets a
 * resource refuse a bound token that arrives without its proof, issue
 * #264). Deriving the set from the profiles keeps "schemes we parse" and
 * "schemes a binding demands" in sync by construction when a
 * `Confirmation` variant is added.
 *
 * Which of the schemes a given token is *allowed* to use is decided by
 * `protectedResourceBindingMw` against the token's `cnf` claim, not here:
 * this module only answers "is there an access token in this header, and
 * what is it?" so every protected resource extracts it the same way.
 */
const ACCESS_TOKEN_SCHEMES = new Set([
    "bearer",
    ...Object.values(BINDING_PROFILES).map((profile) => profile.scheme),
]);
/**
 * Split an `Authorization` header value into the (lowercased) access-token
 * scheme and the token it carries, or `null` when the header carries no
 * access token — absent, malformed, a different scheme (`Basic` client
 * authentication is the case that occurs), or a scheme with an empty
 * credential.
 *
 * The scheme is matched as a whole token, not as a prefix: `BearerToken
 * xyz` is a different scheme and returns `null`, where
 * `startsWith("Bearer ")` would have been fooled by `Bearer` + any suffix
 * only if it also matched the space — but the surrounding endpoints
 * previously used both `startsWith` and case-insensitive regexes, so
 * pinning one behaviour in one place removes the drift.
 *
 * Callers that only need the token use {@link parseAccessTokenHeader};
 * this variant exists for `protectedResourceBindingMw`, which must also
 * check the scheme against the binding the token's `cnf` names.
 */
export const parseAccessTokenAuthorization = (authorization) => {
    if (authorization === undefined)
        return null;
    const separator = authorization.indexOf(" ");
    if (separator === -1)
        return null;
    // RFC 9110 §11.1: the scheme is case-insensitive.
    const scheme = authorization.slice(0, separator).toLowerCase();
    if (!ACCESS_TOKEN_SCHEMES.has(scheme))
        return null;
    // RFC 9110 §5.6.3 allows optional whitespace around a field value.
    const token = authorization.slice(separator + 1).trim();
    return token === "" ? null : { scheme: scheme, token };
};
/**
 * Extract the access token from an `Authorization` header value, or `null`
 * when the header carries no access token. See
 * {@link parseAccessTokenAuthorization} for the exact parsing contract.
 */
export const parseAccessTokenHeader = (authorization) => parseAccessTokenAuthorization(authorization)?.token ?? null;
