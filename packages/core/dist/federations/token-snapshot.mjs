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
const nonEmpty = (value) => typeof value === "string" && value.length > 0;
/**
 * Read a token response the way every adapter does.
 *
 * - **Lifetime.** `expires_in` as the adapter's library read it — the
 *   snapshot sees only the library's answer, so `"1000seconds"` has already
 *   become 1000 — and `expiresAt` dated from `obtainedAt`: when the library
 *   handed the answer over, after it verified any id_token (a JWKS fetch
 *   included), and before the adapter calls UserInfo or anything else. The
 *   delegated reader in `federation-oidc` reads the raw body and the arrival
 *   time instead, and refuses a lifetime that is not a number: a grant's
 *   eligibility judges the lifetime a token was issued with against an
 *   operator's maximum (#593, D5), where a login's expiry only says when a
 *   refresh is due. An absent `expires_in` is `null` on both fields: the
 *   upstream stated no lifetime, and one is not invented for it.
 *   `FederationProfile.expiresAt` asks each adapter for that decision so the
 *   route layer never invents a fallback expiry; an adapter that assumed an
 *   hour was inventing one in its place. It is also what
 *   `POST /oauth/federation/:name/token` already stores for a refresh that
 *   states nothing.
 * - **Scope.** Present exactly when the response carried one, an empty one
 *   included, and `""` for one that is not a string: the session route reads
 *   an absent scope as "as requested" (RFC 6749 §3.3), so an answer that
 *   named nothing usable must not flatten into silence (#647). The bundled
 *   adapters' library refuses a non-string scope first; this holds for any
 *   other caller.
 * - **Refresh token and id_token** only when they are non-empty strings; an
 *   empty one is not a credential.
 * - **Token type** as the library reported it, which is what
 *   `POST /oauth/federation/:name/token` judges before it hands a token on
 *   (#645).
 */
export function federationTokenSnapshot(response, obtainedAt = Date.now()) {
    const expiresIn = typeof response.expires_in === "number" ? response.expires_in : null;
    return {
        accessToken: response.access_token,
        ...(nonEmpty(response.refresh_token) ? { refreshToken: response.refresh_token } : {}),
        ...(nonEmpty(response.id_token) ? { idToken: response.id_token } : {}),
        expiresAt: expiresIn === null ? null : new Date(obtainedAt + expiresIn * 1000),
        expiresIn,
        // Absent only when the answer named none. One present but not a string
        // is an answer that names nothing usable — "" — never silence.
        ...(response.scope === undefined
            ? {}
            : { scope: typeof response.scope === "string" ? response.scope : "" }),
        tokenType: response.token_type,
    };
}
