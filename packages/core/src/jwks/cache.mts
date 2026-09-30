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
 * Default JWKS `Cache-Control: public, max-age` (seconds) when
 * `jwks.cacheMaxAge` is unset. Non-zero because JWKS is the
 * most-polled verifier endpoint; 5 minutes so a rotated key propagates
 * quickly. `max-age` should stay well below the key-overlap window, so a token
 * signed with a newly rotated kid is not rejected longer than the cache
 * lifetime.
 */
export const DEFAULT_JWKS_CACHE_MAX_AGE = 300;

/**
 * Resolves the JWKS `Cache-Control` max-age (seconds), `jwks.cacheMaxAge`.
 * Lenient: the module's section schema already rejects anything but a
 * non-negative integer, so the default here only catches callers that bypass
 * the schema (hand-built config).
 */
export const resolveJwksCacheMaxAge = (config: { jwks?: { cacheMaxAge?: unknown } }): number => {
	const configured = config.jwks?.cacheMaxAge;
	return typeof configured === "number" && Number.isInteger(configured) && configured >= 0
		? configured
		: DEFAULT_JWKS_CACHE_MAX_AGE;
};
