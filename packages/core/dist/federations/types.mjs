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
export function supportsLogout(provider) {
    if (provider == null)
        return false;
    return typeof provider.endSession === "function";
}
export function supportsClaimMapping(p) {
    if (p == null)
        return false;
    return typeof p.mapClaims === "function";
}
export function supportsRefresh(p) {
    if (p == null)
        return false;
    return typeof p.refreshToken === "function";
}
/**
 * The authorization parameters a delegated adapter owns, and which an
 * operator's `authorizationParams` may therefore not set (#593, D17).
 *
 * An exclusion rather than an allowlist: a closed list of permissible vendor
 * parameters would have to be extended for every IdP that invents one, and
 * the ones that matter are the ones this provider computes — the PKCE
 * challenge, the state, the nonce, the redirect it will check the callback
 * against. Setting any of those from configuration is not customisation, it
 * is taking over the security parameters of the flow.
 *
 * It lives here, next to {@link SupportsDelegatedAuthorization}, because two
 * readers need exactly the same set and neither owns it: the adapter that
 * builds the URL refuses these at the point of use, and the federation-grant
 * routes refuse them at boot, where an operator finds out before a user is
 * standing in front of a consent page.
 */
export const RESERVED_DELEGATED_AUTHORIZATION_PARAMS = new Set([
    "client_id",
    "response_type",
    "redirect_uri",
    "state",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "scope",
    "resource",
    "request",
    "request_uri",
    "response_mode",
]);
/**
 * The id_token claims {@link DelegatedCodeExchangeRequest.identityClaims} may
 * not name (#611): the protocol's own bindings and the token's and session's
 * identifiers, which are the adapter's to check and say nothing stable about
 * who a person is — and the names that would reach an object's prototype.
 */
export const RESERVED_IDENTITY_CLAIMS = new Set([
    "sub",
    "iss",
    "aud",
    "azp",
    "nonce",
    "exp",
    "iat",
    "nbf",
    "auth_time",
    "at_hash",
    "c_hash",
    "s_hash",
    "jti",
    // Entra's token identifier — its `jti` by another name.
    "uti",
    "sid",
    "__proto__",
    "constructor",
    "prototype",
]);
const IDENTITY_CLAIM_NAME = /^[\x21-\x7E]{1,256}$/;
/**
 * Why `names` is not a usable `identityClaims` list, or `undefined` when it
 * is (#611). Case-sensitive names of printable ASCII without spaces, none
 * reserved, none repeated — refused rather than trimmed or de-duplicated,
 * because a list an operator wrote wrongly is a list they meant differently.
 * Shared by the adapter, which refuses at the point of use, and the grant
 * routes, which refuse at boot.
 */
export function identityClaimsProblem(names) {
    const seen = new Set();
    for (const name of names) {
        if (typeof name !== "string" || !IDENTITY_CLAIM_NAME.test(name)) {
            return `identityClaims: ${JSON.stringify(name)} is not a claim name (printable ASCII, no spaces)`;
        }
        if (RESERVED_IDENTITY_CLAIMS.has(name)) {
            return `identityClaims: "${name}" is a claim the protocol owns, not an identity to match on`;
        }
        if (seen.has(name))
            return `identityClaims: "${name}" is listed twice`;
        seen.add(name);
    }
    return undefined;
}
/**
 * The claims asked for, out of a VERIFIED id_token's (#611): own properties
 * only, non-empty strings only, nothing coerced. A claim absent or of another
 * type is left out rather than failed on here — the caller knows which ones
 * it cannot do without.
 */
export function selectIdentityClaims(claims, names) {
    const selected = {};
    for (const name of names) {
        if (!Object.hasOwn(claims, name))
            continue;
        const value = claims[name];
        if (typeof value === "string" && value.length > 0)
            selected[name] = value;
    }
    return selected;
}
export function supportsDelegatedAuthorization(p) {
    if (p == null)
        return false;
    const candidate = p;
    return (typeof candidate.buildDelegatedAuthorizationUrl === "function" &&
        typeof candidate.exchangeDelegatedCode === "function" &&
        typeof candidate.refreshDelegatedToken === "function");
}
