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
 * POST /oauth/webauthn/authentication/options — authentication ceremony options endpoint.
 *
 * Returns a PublicKeyCredentialRequestOptionsJSON for the client to initiate a
 * WebAuthn authentication ceremony (passkey assertion).
 *
 * Security properties (spec §2.4, revised by #281):
 *   - Unauthenticated by design: the passkey authentication IS the authentication
 *     event, not a follow-up to one. No req.webauthnSubject check.
 *   - Rate limiting is MOUNTED, not assumed. `module.mts` puts core's shared
 *     `createRateLimitGuard` in front of this handler under the
 *     {@link WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG} key, falling back
 *     to a per-process limiter when no shared `rateLimiter` component is wired.
 *     The pre-#281 code carried a comment saying rate limiting was "composed
 *     externally at module-wiring time" and nothing composed it.
 *   - Challenge is stored under the fixed, non-user-scoped namespace
 *     "webauthn:authentication". The userId is resolved post-assertion from the
 *     credential record returned by the authenticator — the client does NOT
 *     declare which user they are (that would be a proof-of-possession bypass).
 *   - The optional `userId` body field is bounded to the WebAuthn §5.4.3
 *     user-handle shape (1..64 UTF-8 bytes, no control characters) BEFORE it
 *     reaches any store, so an unauthenticated caller cannot push an arbitrary
 *     blob into a credential lookup.
 *   - Enumeration resistance: the response is the discoverable-credential shape
 *     for every caller. `allowCredentials` is NEVER derived from the body
 *     unless the deployment sets `allowCredentialsForKnownUser: true`, and with
 *     that flag off the credential store is not consulted at all — so the
 *     response body, its key set, and the work done to produce it are identical
 *     whether or not the named account exists.
 *
 * `createAuthenticationOptionsHandler` is NOT barrel-exported from the package
 * index — it is internal to the webauthn module, which mounts it (Task 31).
 * {@link WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG} IS exported, because
 * it is an operator-facing name rather than an internal one: it is the `limits`
 * key a `RateLimiter` adapter resolves this route's spec by.
 *
 * Cross-refs: Plan T29 / spec §2.4 / issue #281
 */

import type { ChallengeStore, WebAuthnCredentialStore } from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import { z } from "zod";
import type { WebAuthnConfig } from "../config.mjs";
import { generateAuthenticationOptionsForUser } from "../internal/options.mjs";

// ---------------------------------------------------------------------------
// Rate-limit key
// ---------------------------------------------------------------------------

/**
 * Endpoint tag for `createRateLimitGuard` — the `<tag>:ip:<ip>` key prefix by
 * which an adapter resolves this route's spec, and the `tag` field on the
 * guard's log and audit emissions.
 *
 * Exported because it is an operator-facing name: it is what goes in
 * `memoryRateLimiter.limits` / `redisRateLimiter.limits` to override the
 * per-endpoint spec. Contains no `:` — the memory adapter derives the spec
 * key by splitting on the first colon.
 */
export const WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG = "webauthn-authentication-options";

// ---------------------------------------------------------------------------
// Body schema
// ---------------------------------------------------------------------------

/**
 * WebAuthn §5.4.3 caps the user handle at 64 bytes. `registrationOptions.mts`
 * already enforces the same bound on the handle taken from the authenticated
 * session; this is the same constraint applied to the one place a caller can
 * name a handle themselves.
 */
const MAX_USER_ID_BYTES = 64;

/** C0 and C1 control characters — never part of a legitimate opaque handle. */
// biome-ignore lint/suspicious/noControlCharactersInRegex: bounding the accepted handle to printable characters is the point of this check.
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/;

/**
 * The single description used for every rejection of this body.
 *
 * Deliberately one string: a per-reason message would let a caller learn
 * something about the value they sent, and — more importantly — keeps the
 * failure response independent of anything the server knows about the account.
 */
const INVALID_USER_ID_DESCRIPTION =
	"userId must be an opaque handle of 1-64 UTF-8 bytes with no control characters (WebAuthn §5.4.3)";

const userIdSchema = z
	// `.max` on code units first: a UTF-8 encoding is never shorter than the
	// code-unit count, so this rejects an oversized value without encoding it.
	// Without it a 100kb body (the express.json ceiling) would be encoded in
	// full before being thrown away.
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
	// Rate limiting is mounted by `module.mts` in front of this handler
	// (core's `createRateLimitGuard`), so it is middleware rather than a
	// handler-level dep — but it is no longer merely assumed. See #281.
}

// ---------------------------------------------------------------------------
// Handler factory
// ---------------------------------------------------------------------------

/**
 * Creates an Express RequestHandler for POST /oauth/webauthn/authentication/options.
 *
 * Unauthenticated — no req.webauthnSubject check.
 *
 * @param deps - Injected dependencies (config, challengeStore, credentialStore).
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

		// #281: `allowCredentials` is derived ONLY under the explicit opt-in.
		// With the opt-in off there is no store call for anyone, so there is no
		// per-account work to time and no shape to compare — the discoverable
		// response is the only response this endpoint produces.
		//
		// With the opt-in on, a deployment has accepted the enumeration oracle
		// in exchange for supporting non-discoverable authenticators; the 200 /
		// no-error-shape mitigation from the original design is all that remains
		// there, and it is not enough on its own. See the config JSDoc.
		const allowCredentials =
			deps.config.allowCredentialsForKnownUser && userId !== undefined
				? await deps.credentialStore.listByUserId(userId)
				: [];

		// Generate a fresh 32-byte random challenge for this ceremony.
		const challenge = crypto.getRandomValues(new Uint8Array(32));

		// Generate the PublicKeyCredentialRequestOptionsJSON.
		// Empty allowCredentials → discoverable-credentials flow (SimpleWebAuthn
		// omits the field from the JSON per spec §2.4 when undefined is passed).
		const options = await generateAuthenticationOptionsForUser({
			config: deps.config,
			allowCredentials,
			challenge,
		});

		// Store the challenge under the fixed, non-user-scoped namespace.
		// userId is resolved post-assertion from the credential record — the
		// authenticator identifies the user, not the client request.
		const expiresAtMs = Date.now() + deps.config.challengeTtlMs;
		await deps.challengeStore.issue("webauthn:authentication", options.challenge, expiresAtMs);

		res.status(200).json(options);
	};
}
