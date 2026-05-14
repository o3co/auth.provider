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
 * POST /oauth/webauthn/registration/options — registration ceremony options endpoint.
 *
 * Returns a PublicKeyCredentialCreationOptionsJSON to be forwarded to the client.
 * Requires an authenticated subject on `req.webauthnSubject` — set by upstream
 * session / bearer middleware. Authorization strength is a consumer-policy concern;
 * this endpoint trusts upstream auth.
 *
 * Security properties (spec §2.4):
 *   - userId is taken from the authenticated session, NOT the request body —
 *     prevents victim-targeted enrollment (cross-user challenge injection).
 *   - Challenge is scoped to `webauthn:registration:${userId}` so a challenge
 *     issued for user A cannot be consumed by user B.
 *   - challengeTtlMs controls the window; default 120_000 ms per spec §2.4.1.
 *   - excludeCredentials is populated from the credential store to prevent
 *     re-registering an already-registered authenticator for this user.
 *
 * NOT barrel-exported from the package index — internal to the webauthn module
 * until Task 31 wires the router.
 *
 * Cross-refs: Plan T27 / spec §2.4 / §2.4.1
 */

import type { ChallengeStore, WebAuthnCredentialStore } from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import type { WebAuthnConfig } from "../config.mjs";
import { generateRegistrationOptionsForUser } from "../internal/options.mjs";

// WebAuthnSubject type + Express Request augmentation live in request.mts and
// are barrel-exported. Re-export here so importers of this internal file still
// see the type without a second hop.
export type { WebAuthnSubject } from "../request.mjs";

// ---------------------------------------------------------------------------
// Handler deps
// ---------------------------------------------------------------------------

export interface RegistrationOptionsDeps {
	readonly config: WebAuthnConfig;
	readonly challengeStore: ChallengeStore;
	readonly credentialStore: WebAuthnCredentialStore;
	// session/bearer auth resolved upstream — endpoint trusts req.webauthnSubject
}

// ---------------------------------------------------------------------------
// Handler factory
// ---------------------------------------------------------------------------

/**
 * Creates an Express RequestHandler for POST /oauth/webauthn/registration/options.
 *
 * @param deps - Injected dependencies (config, challengeStore, credentialStore).
 * @returns RequestHandler suitable for mounting on an Express router.
 */
export function createRegistrationOptionsHandler(deps: RegistrationOptionsDeps): RequestHandler {
	return async (req: Request, res: Response) => {
		// §2.4: Require authenticated subject — auth strength is consumer-policy concern.
		const subject = req.webauthnSubject;
		if (!subject) {
			res.status(401).json({ error: "unauthorized" });
			return;
		}

		// userId is always taken from the authenticated session — request body cannot
		// override (prevents victim-targeted enrollment per spec §2.4).
		const { userId } = subject;

		// Wave 1 post-merge audit M-2: enforce WebAuthn §5.4.3 user-handle constraints
		// at the boundary. WebAuthn mandates a 1..64-byte opaque user-handle; longer
		// values are rejected by authenticators at runtime, and consumer misuse
		// (e.g. passing `req.user.email` here) syncs PII to the authenticator. The
		// interface JSDoc already documents this MUST, but the library now enforces
		// it so misconfigurations fail loudly with a 500 (consumer bug, not a 400).
		const userIdByteLength = new TextEncoder().encode(userId).length;
		if (userIdByteLength < 1 || userIdByteLength > 64) {
			res.status(500).json({
				error: "server_error",
				error_description:
					"webauthnSubject.userId must be 1-64 bytes per WebAuthn §5.4.3 (opaque user-handle)",
			});
			return;
		}

		const userName = subject.userName ?? userId;
		const userDisplayName = subject.userDisplayName ?? userName;

		// Populate excludeCredentials from the credential store to prevent
		// re-registering an already-registered authenticator for this user.
		const existing = await deps.credentialStore.listByUserId(userId);

		// Generate a fresh random challenge for this ceremony.
		const challenge = crypto.getRandomValues(new Uint8Array(32));

		// Generate the PublicKeyCredentialCreationOptionsJSON.
		// options.challenge is base64url-encoded by @simplewebauthn/server.
		const options = await generateRegistrationOptionsForUser({
			config: deps.config,
			userId,
			userName,
			userDisplayName,
			excludeCredentials: existing,
			challenge,
		});

		// Store the challenge under the user-scoped namespace to prevent cross-user
		// replay. The value stored is the base64url string from SimpleWebAuthn so
		// it can be compared directly against the client response in the verify step.
		const expiresAtMs = Date.now() + deps.config.challengeTtlMs;
		await deps.challengeStore.issue(
			`webauthn:registration:${userId}`,
			options.challenge,
			expiresAtMs,
		);

		res.status(200).json(options);
	};
}
