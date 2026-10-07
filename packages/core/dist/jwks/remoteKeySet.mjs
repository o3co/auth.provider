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
/**
 * A remote JSON Web Key Set — the one place this library turns a `jwks_uri`
 * into a verification key resolver.
 *
 * jose's `createRemoteJWKSet` caches the document, refetches on an unknown
 * `kid` (with a cooldown, so a flood of bad kids is not a flood of fetches)
 * and refreshes it after `cacheMaxAge`. That cache lives in the resolver, so a
 * resolver made per request is a fetch per request; the memo here is what
 * makes a rotation cost one refetch.
 *
 * Two consumers had their own copy — `private_key_jwt` client assertions
 * (#484) and the trust-registry assertion verifier (#525) — with the same
 * memo and the same tuning, and only the first took a fetch. A deployment
 * behind an egress proxy could fetch a client's keys and not a trusted
 * issuer's (v0.13.0 audit). Both build on this now.
 */
import { createRemoteJWKSet, customFetch } from "jose";
/** Fetch timeout for a key set. */
export const DEFAULT_REMOTE_JWKS_TIMEOUT_MS = 5_000;
/** Minimum interval between refetches an unknown `kid` triggers. */
export const DEFAULT_REMOTE_JWKS_COOLDOWN_MS = 30_000;
/** How long a fetched key set is served without refetching. */
export const DEFAULT_REMOTE_JWKS_CACHE_MAX_AGE_MS = 600_000;
export function createRemoteKeySetCache(options = {}) {
    const sets = new Map();
    return {
        keySetFor(uri, tuning = {}) {
            const timeoutMs = tuning.timeoutMs ?? DEFAULT_REMOTE_JWKS_TIMEOUT_MS;
            const cooldownMs = tuning.cooldownMs ?? DEFAULT_REMOTE_JWKS_COOLDOWN_MS;
            const cacheMaxAgeMs = tuning.cacheMaxAgeMs ?? DEFAULT_REMOTE_JWKS_CACHE_MAX_AGE_MS;
            const key = JSON.stringify([uri, timeoutMs, cooldownMs, cacheMaxAgeMs]);
            let set = sets.get(key);
            if (!set) {
                set = createRemoteJWKSet(new URL(uri), {
                    timeoutDuration: timeoutMs,
                    cooldownDuration: cooldownMs,
                    cacheMaxAge: cacheMaxAgeMs,
                    ...(options.fetch ? { [customFetch]: options.fetch } : {}),
                });
                sets.set(key, set);
            }
            return set;
        },
    };
}
