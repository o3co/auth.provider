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

import type { RateLimitSpec } from "./types.mjs";
import { isUsableRateLimitSpec } from "./usableSpec.mjs";

/**
 * The key prefix `POST /oauth/webauthn/authentication/options` limits under
 * (`webauthn-authentication-options:ip:<ip>`). Defined here, in core, so the
 * seed below and the route that keys on it share one name;
 * `@o3co/auth-provider-webauthn` exports it as
 * `WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG` rather than restating it.
 * Contains no `:`, since an adapter takes the prefix up to the first colon.
 */
export const WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_PREFIX = "webauthn-authentication-options";

/**
 * Seed a rate-limiter adapter's `limits` with the WebAuthn options route's
 * spec, drawn from `config.webauthn.rateLimit.authenticationOptions`.
 *
 * The route is unauthenticated and writes a challenge per request; its budget
 * (reference default 30 per 60 s) lives in the WebAuthn section. The route
 * built its per-process fallback from it, but a shared limiter, which a
 * scaled deployment must wire, resolves the prefix from its own `limits`,
 * and nothing seeded it: the route ran on the adapter's `defaultLimit` of
 * 60 per 60 s, silently.
 *
 * Same shape as `resolveLoginLimitSpec` (#270) and
 * `resolveDeviceVerificationLimitSpec` (#448): one config key is the source
 * of truth, seeded into each adapter unless the operator declared the prefix
 * explicitly. An explicit entry is a statement about this adapter and wins.
 * A spec the one predicate (`isUsableRateLimitSpec`) does not accept is not
 * seeded, as the other two seeds do not seed one; the WebAuthn schema refuses
 * it at the config boundary.
 *
 * @param limits  The adapter's own configured limits.
 * @param config  The full application config (only
 *                `webauthn.rateLimit.authenticationOptions` is read).
 */
export const resolveWebAuthnAuthenticationOptionsLimitSpec = (
	limits: Readonly<Record<string, RateLimitSpec>>,
	config: unknown,
): Record<string, RateLimitSpec> => {
	const result: Record<string, RateLimitSpec> = { ...limits };
	if (result[WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_PREFIX] !== undefined) return result;

	const spec = (
		config as { webauthn?: { rateLimit?: { authenticationOptions?: unknown } } } | undefined
	)?.webauthn?.rateLimit?.authenticationOptions;
	if (!isUsableRateLimitSpec(spec)) return result;

	result[WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_PREFIX] = {
		limit: spec.limit,
		windowSeconds: spec.windowSeconds,
	};
	return result;
};
