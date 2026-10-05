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
 * POST /oauth/webauthn/authentication/options: returns the PublicKeyCredentialRequestOptionsJSON
 * that starts a passkey assertion. The handler is internal to the module; only the rate-limit
 * tag is exported.
 *
 * Unauthenticated by design (the assertion is the authentication event), so `module.mts` mounts
 * a rate limit in front of it and the endpoint reveals nothing about accounts. The options are
 * always the discoverable-credential shape, with no `allowCredentials`: the body is not read and
 * no credential store is consulted, so the response and the work behind it are the same for
 * every caller. The challenge is stored under the fixed namespace "webauthn:authentication": the
 * user comes from the assertion's user handle, never from the client. A store outage is 503
 * temporarily_unavailable.
 */

import type { ChallengeStore, Logger } from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import type { WebAuthnConfig } from "../config.mjs";
import { generateAuthenticationOptionsForUser } from "../internal/options.mjs";
import { refuseCeremonyStoreUnavailable } from "../internal/storeUnavailable.mjs";

// ---------------------------------------------------------------------------
// Rate-limit key
// ---------------------------------------------------------------------------

/**
 * Endpoint tag for `createRateLimitGuard`: the `<tag>:ip:<ip>` key prefix a limiter resolves this
 * route's limit by, and the `tag` on the guard's log and audit events. The module claims it with no
 * budget; operators set the route's limit as the key in `core-rate-limiter-memory.limits` /
 * `redis-rate-limiter.limits`, else the limiter's `defaultLimit` applies. Contains no `:`, since a
 * limiter takes the prefix up to the first colon.
 */
export const WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG = "webauthn-authentication-options";

// ---------------------------------------------------------------------------
// Handler deps
// ---------------------------------------------------------------------------

export interface AuthenticationOptionsDeps {
	readonly config: WebAuthnConfig;
	readonly challengeStore: ChallengeStore;
	/** Where a store outage is logged. */
	readonly logger: Pick<Logger, "error">;
	// Rate limiting is middleware `module.mts` mounts in front of this handler, not a dep.
}

// ---------------------------------------------------------------------------
// Handler factory
// ---------------------------------------------------------------------------

/**
 * Creates an Express RequestHandler for POST /oauth/webauthn/authentication/options.
 *
 * Unauthenticated — no req.webauthnSubject check.
 *
 * @param deps - Injected dependencies (config, challengeStore, logger).
 * @returns RequestHandler suitable for mounting on an Express router.
 */
export function createAuthenticationOptionsHandler(
	deps: AuthenticationOptionsDeps,
): RequestHandler {
	return async (_req: Request, res: Response) => {
		// Generate a fresh 32-byte random challenge for this ceremony.
		const challenge = crypto.getRandomValues(new Uint8Array(32));

		// An empty allowCredentials yields the discoverable-credential flow.
		const options = await generateAuthenticationOptionsForUser({
			config: deps.config,
			allowCredentials: [],
			challenge,
		});

		// A fixed, non-user-scoped namespace: the authenticator identifies the user, not the
		// request.
		// Recorded with the challenge: the passkey grant stamps `auth_time` from it.
		const issuedAtMs = Date.now();
		const expiresAtMs = issuedAtMs + deps.config.challengeTtlMs;
		try {
			await deps.challengeStore.issue(
				"webauthn:authentication",
				options.challenge,
				expiresAtMs,
				issuedAtMs,
			);
		} catch (err) {
			refuseCeremonyStoreUnavailable(
				res,
				deps.logger,
				{ site: "authentication_options", store: "challenge", step: "issue" },
				err,
			);
			return;
		}

		res.status(200).json(options);
	};
}
