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
 * a rate limit in front of it and the endpoint reveals nothing about accounts. The challenge is
 * stored under the fixed namespace "webauthn:authentication": the user comes from the credential
 * after the assertion, never from the client. The optional `userId` is bounded to the WebAuthn
 * §5.4.3 user-handle shape before any store sees it. Unless `allowCredentialsForKnownUser` is
 * set, the credential store is not consulted, so the response and the work behind it are the same
 * whether or not the account exists. A store outage is 503 temporarily_unavailable, logged
 * without the caller's `userId`.
 */

import type { ChallengeStore, Logger, WebAuthnCredentialStore } from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import { z } from "zod";
import type { WebAuthnConfig } from "../config.mjs";
import { generateAuthenticationOptionsForUser } from "../internal/options.mjs";
import { refuseCeremonyStoreUnavailable } from "../internal/storeUnavailable.mjs";

// ---------------------------------------------------------------------------
// Rate-limit key
// ---------------------------------------------------------------------------

/**
 * Endpoint tag for `createRateLimitGuard`: the `<tag>:ip:<ip>` key prefix a limiter resolves this
 * route's budget by, and the `tag` on the guard's log and audit events. The module contributes
 * `webauthn.rateLimit.authenticationOptions` as the budget under it; operators use it as the key
 * in `core-rate-limiter-memory.limits` / `redis-rate-limiter.limits` to override that. Contains no `:`,
 * since a limiter takes the prefix up to the first colon.
 */
export const WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG = "webauthn-authentication-options";

// ---------------------------------------------------------------------------
// Body schema
// ---------------------------------------------------------------------------

/**
 * WebAuthn §5.4.3 caps the user handle at 64 bytes; `registrationOptions.mts` applies the same
 * bound to the session-derived handle.
 */
const MAX_USER_ID_BYTES = 64;

/** C0 and C1 control characters — never part of a legitimate opaque handle. */
// biome-ignore lint/suspicious/noControlCharactersInRegex: bounding the accepted handle to printable characters is the point of this check.
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/;

/**
 * The one description for every rejection of this body, so the failure reveals nothing about the
 * value sent or about what the server knows of the account.
 */
const INVALID_USER_ID_DESCRIPTION =
	"userId must be an opaque handle of 1-64 UTF-8 bytes with no control characters (WebAuthn section 5.4.3)";

const userIdSchema = z
	// `.max` on code units first: UTF-8 is never shorter than the code-unit count, so an
	// oversized value (up to the 100kb body limit) is refused without being encoded.
	.string()
	.max(MAX_USER_ID_BYTES)
	.refine((value) => !CONTROL_CHARACTERS.test(value))
	.refine((value) => {
		const byteLength = new TextEncoder().encode(value).length;
		return byteLength >= 1 && byteLength <= MAX_USER_ID_BYTES;
	});

const bodySchema = z.object({
	userId: userIdSchema.optional(),
});

// ---------------------------------------------------------------------------
// Handler deps
// ---------------------------------------------------------------------------

export interface AuthenticationOptionsDeps {
	readonly config: WebAuthnConfig;
	readonly challengeStore: ChallengeStore;
	readonly credentialStore: WebAuthnCredentialStore;
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
 * @param deps - Injected dependencies (config, challengeStore, credentialStore, logger).
 * @returns RequestHandler suitable for mounting on an Express router.
 */
export function createAuthenticationOptionsHandler(
	deps: AuthenticationOptionsDeps,
): RequestHandler {
	return async (req: Request, res: Response) => {
		// Bound the identifier before anything else touches it. This runs
		// regardless of `allowCredentialsForKnownUser` so that flipping the flag
		// changes exactly one thing — whether allowCredentials is derived — and
		// not what the endpoint accepts.
		const parsed = bodySchema.safeParse(req.body ?? {});
		if (!parsed.success) {
			res.status(400).json({
				error: "invalid_request",
				error_description: INVALID_USER_ID_DESCRIPTION,
			});
			return;
		}

		const { userId } = parsed.data;

		// `allowCredentials` only under the opt-in. Without it no request reaches the store, so
		// there is no per-account timing or shape to compare. With it, the deployment has
		// accepted the enumeration oracle to support non-discoverable authenticators (see
		// `allowCredentialsForKnownUser` in config.mts).
		let allowCredentials: Awaited<ReturnType<typeof deps.credentialStore.listByUserId>> = [];
		if (deps.config.allowCredentialsForKnownUser && userId !== undefined) {
			try {
				allowCredentials = await deps.credentialStore.listByUserId(userId);
			} catch (err) {
				refuseCeremonyStoreUnavailable(
					res,
					deps.logger,
					{ site: "authentication_options", store: "webauthn_credential", step: "list" },
					err,
				);
				return;
			}
		}

		// Generate a fresh 32-byte random challenge for this ceremony.
		const challenge = crypto.getRandomValues(new Uint8Array(32));

		// An empty allowCredentials yields the discoverable-credential flow.
		const options = await generateAuthenticationOptionsForUser({
			config: deps.config,
			allowCredentials,
			challenge,
		});

		// A fixed, non-user-scoped namespace: the authenticator identifies the user, not the
		// request.
		const expiresAtMs = Date.now() + deps.config.challengeTtlMs;
		try {
			await deps.challengeStore.issue("webauthn:authentication", options.challenge, expiresAtMs);
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
