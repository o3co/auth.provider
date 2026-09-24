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
 * `POST /oauth/webauthn/authentication/options` limits under
 * `webauthn-authentication-options:ip:<ip>`, and its budget is configured at
 * `webauthn.rateLimit.authenticationOptions` (reference default 30 / 60 s).
 * Only the route's per-process fallback was built from it: a shared limiter,
 * which a scaled deployment must wire, resolved the prefix from its own
 * `limits`, found nothing, and served its 60 / 60 s default on an
 * unauthenticated route. Same fix as `login` (#270) and
 * `device_verification` (#448): seeded, unless the operator declared the
 * prefix explicitly.
 */

import { describe, expect, it } from "vitest";
import {
	resolveWebAuthnAuthenticationOptionsLimitSpec,
	WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_PREFIX,
} from "#/ratelimit/webauthnSpec.mjs";

const configured = (limit: unknown, windowSeconds: unknown) => ({
	webauthn: { rateLimit: { authenticationOptions: { limit, windowSeconds } } },
});

describe("resolveWebAuthnAuthenticationOptionsLimitSpec", () => {
	it("names the prefix the options route keys on", () => {
		expect(WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_PREFIX).toBe(
			"webauthn-authentication-options",
		);
	});

	it("seeds the prefix from webauthn.rateLimit.authenticationOptions", () => {
		const limits = resolveWebAuthnAuthenticationOptionsLimitSpec({}, configured(30, 60));
		expect(limits[WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_PREFIX]).toEqual({
			limit: 30,
			windowSeconds: 60,
		});
	});

	it("leaves an operator-declared spec for the prefix alone", () => {
		const limits = resolveWebAuthnAuthenticationOptionsLimitSpec(
			{ [WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_PREFIX]: { limit: 5, windowSeconds: 60 } },
			configured(30, 60),
		);
		expect(limits[WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_PREFIX]).toEqual({
			limit: 5,
			windowSeconds: 60,
		});
	});

	it("preserves every other prefix, and does not mutate what it was handed", () => {
		const input = { token: { limit: 100, windowSeconds: 60 } };
		const limits = resolveWebAuthnAuthenticationOptionsLimitSpec(input, configured(30, 60));
		expect(limits.token).toEqual({ limit: 100, windowSeconds: 60 });
		expect(input).toEqual({ token: { limit: 100, windowSeconds: 60 } });
	});

	it("does not seed when the config carries no usable spec, as the other seeds do not", () => {
		// The WebAuthn schema refuses these at the config boundary; a hand-built
		// config that never passed it is judged by the one predicate.
		expect(
			resolveWebAuthnAuthenticationOptionsLimitSpec({}, {})[
				WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_PREFIX
			],
		).toBeUndefined();
		for (const [limit, windowSeconds] of [
			[0, 60],
			[30, 0],
			[30, 1.5],
			["30", 60],
			[30, 1e13],
		]) {
			expect(
				resolveWebAuthnAuthenticationOptionsLimitSpec({}, configured(limit, windowSeconds))[
					WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_PREFIX
				],
				`limit=${String(limit)} windowSeconds=${String(windowSeconds)}`,
			).toBeUndefined();
		}
	});
});
