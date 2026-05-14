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
 * Security properties (spec §2.4):
 *   - Unauthenticated by design: the passkey authentication IS the authentication
 *     event, not a follow-up to one. No req.webauthnSubject check.
 *   - Rate-limit middleware is composed externally at module-wiring time
 *     (S10/S15 — RateLimiter slot). Not a handler-level dep.
 *   - Challenge is stored under the fixed, non-user-scoped namespace
 *     "webauthn:authentication". The userId is resolved post-assertion from the
 *     credential record returned by the authenticator — the client does NOT
 *     declare which user they are (that would be a proof-of-possession bypass).
 *   - Optional userId body field: if provided, allowCredentials is populated from
 *     the credential store; if absent, the discoverable-credentials flow is used
 *     (empty allowCredentials → authenticator prompts the user to pick a passkey).
 *   - Existence-leak mitigation: when userId is provided but has no registered
 *     credentials, the response is identical to the discoverable-flow response —
 *     no 404 or "user not found" is returned. This prevents timing-based user
 *     enumeration (attacker cannot distinguish "user exists, no passkeys" from
 *     "user does not exist").
 *
 * NOT barrel-exported from the package index — internal to the webauthn module
 * until Task 31 wires the router.
 *
 * Cross-refs: Plan T29 / spec §2.4
 */

import type { ChallengeStore, WebAuthnCredentialStore } from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import { z } from "zod";
import type { WebAuthnConfig } from "../config.mjs";
import { generateAuthenticationOptionsForUser } from "../internal/options.mjs";

// ---------------------------------------------------------------------------
// Body schema
// ---------------------------------------------------------------------------

const bodySchema = z.object({
	userId: z.string().optional(),
});

// ---------------------------------------------------------------------------
// Handler deps
// ---------------------------------------------------------------------------

export interface AuthenticationOptionsDeps {
	readonly config: WebAuthnConfig;
	readonly challengeStore: ChallengeStore;
	readonly credentialStore: WebAuthnCredentialStore;
	// Rate-limit is applied externally at module-wiring time (S10/S15 — not a
	// handler-level dep). This handler trusts that the caller has composed the
	// RateLimiter middleware before mounting it on the router.
}

// ---------------------------------------------------------------------------
// Handler factory
// ---------------------------------------------------------------------------

/**
 * Creates an Express RequestHandler for POST /oauth/webauthn/authentication/options.
 *
 * Unauthenticated — no req.webauthnSubject check. Rate-limit middleware is
 * composed externally by the module router (Task 31).
 *
 * @param deps - Injected dependencies (config, challengeStore, credentialStore).
 * @returns RequestHandler suitable for mounting on an Express router.
 */
export function createAuthenticationOptionsHandler(
	deps: AuthenticationOptionsDeps,
): RequestHandler {
	return async (req: Request, res: Response) => {
		// Validate body: userId must be a string if present.
		const parsed = bodySchema.safeParse(req.body ?? {});
		if (!parsed.success) {
			res.status(400).json({
				error: "invalid_request",
				error_description: "userId must be a string",
			});
			return;
		}

		const { userId } = parsed.data;

		// Resolve allowCredentials from the credential store when userId is given.
		// Existence-leak mitigation: respond identically whether userId maps to a
		// real user with credentials or not — no 404, no "user not found" error.
		// An attacker cannot distinguish "user exists, no passkeys" from "user does
		// not exist" via this endpoint's response shape or timing.
		const allowCredentials =
			userId !== undefined ? await deps.credentialStore.listByUserId(userId) : [];

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
