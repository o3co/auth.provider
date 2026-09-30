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
 * POST /oauth/webauthn/registration/verify — registration ceremony verify endpoint.
 *
 * Consumes the single-use challenge issued by the options endpoint, verifies the
 * authenticator's attestation response via SimpleWebAuthn, and persists the new
 * credential to the store.
 *
 * Security properties:
 *   - Requires an authenticated subject on `req.webauthnSubject` (set by upstream
 *     session / bearer middleware). Returns 401 if absent.
 *   - Challenge is consumed atomically via ChallengeCeremony for the user-scoped
 *     namespace `webauthn:registration:${userId}`. Any outcome other than "consumed"
 *     (i.e. "unknown" or "replayed") immediately rejects with 400 challenge_invalid —
 *     replay rejection is the redemption primitive; no separate seen-challenge tracking.
 *   - userId is always taken from the authenticated session (req.webauthnSubject.userId),
 *     NOT from the request body — prevents victim-targeted enrollment.
 *   - nickname, when present, is a string of 1–64 characters.
 *   - Multi-origin support: config.origin[] is passed to verifyWebAuthnAttestation.
 *   - A top origin the browser reports must be one of config.topOrigin, for a
 *     cross-origin ceremony — the rule an assertion is held to — else 400
 *     top_origin_mismatch.
 *   - A store that cannot answer — the ceremony's consume or the credential
 *     insert — is 503 temporarily_unavailable, logged once at error level as
 *     `webauthn_ceremony_store_unavailable` (`../internal/storeUnavailable.mts`).
 *     Either may land after the challenge was consumed, and an insert whose
 *     reply was lost may have stored the credential: the client's retry of the
 *     same response is then 400 challenge_invalid, and a new ceremony's
 *     `excludeCredentials` names the stored credential.
 *
 * NOT barrel-exported from the package index; `../module.mts` mounts it.
 */

import {
	type ChallengeCeremony,
	type Logger,
	WebAuthnCredentialStorageError,
	type WebAuthnCredentialStore,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import { z } from "zod";
import type { WebAuthnConfig } from "../config.mjs";
import { refuseCeremonyStoreUnavailable } from "../internal/storeUnavailable.mjs";
import { verifyWebAuthnAttestation } from "../internal/verification.mjs";

// ---------------------------------------------------------------------------
// Nickname validation constant
// ---------------------------------------------------------------------------

/**
 * Maximum length for a credential nickname, as JS string `.length` (UTF-16 code
 * units, which for BMP characters are code points): large enough for typical
 * display names and short emoji sequences, small enough to avoid storage abuse.
 */
const NICKNAME_MAX_LENGTH = 64;

// ---------------------------------------------------------------------------
// Request body schema
// ---------------------------------------------------------------------------

/**
 * Zod schema for the verify request body.
 *
 * `response` need only be an object: SimpleWebAuthn validates the
 * RegistrationResponseJSON shape inside verifyWebAuthnAttestation. Any `userId`
 * field in the body is intentionally not parsed — the endpoint reads userId
 * exclusively from req.webauthnSubject.
 */
const bodySchema = z.object({
	response: z.object({}).passthrough(),
	nickname: z
		.string()
		.min(1, "nickname must not be empty")
		.max(NICKNAME_MAX_LENGTH, `nickname must not exceed ${NICKNAME_MAX_LENGTH} characters`)
		.optional(),
});

// ---------------------------------------------------------------------------
// Handler deps
// ---------------------------------------------------------------------------

export interface RegistrationVerifyDeps {
	readonly config: WebAuthnConfig;
	readonly challengeCeremony: ChallengeCeremony;
	readonly credentialStore: WebAuthnCredentialStore;
	/** Where a store outage is logged. */
	readonly logger: Pick<Logger, "error">;
	// session/bearer auth resolved upstream — endpoint trusts req.webauthnSubject
}

// ---------------------------------------------------------------------------
// Handler factory
// ---------------------------------------------------------------------------

/**
 * Creates an Express RequestHandler for POST /oauth/webauthn/registration/verify.
 *
 * @param deps - Injected dependencies (config, challengeCeremony, credentialStore, logger).
 * @returns RequestHandler suitable for mounting on an Express router.
 */
export function createRegistrationVerifyHandler(deps: RegistrationVerifyDeps): RequestHandler {
	return async (req: Request, res: Response) => {
		// Require authenticated subject — auth strength is consumer-policy concern.
		const subject = req.webauthnSubject;
		if (!subject) {
			res.status(401).json({ error: "unauthorized" });
			return;
		}

		// userId is always taken from the authenticated session — request body cannot
		// override (prevents victim-targeted enrollment).
		const { userId } = subject;

		// WebAuthn §5.4.3 user-handle constraints (1..64 bytes opaque). Mirrors the
		// registrationOptions gate so the verify endpoint is independently safe.
		const userIdByteLength = new TextEncoder().encode(userId).length;
		if (userIdByteLength < 1 || userIdByteLength > 64) {
			// The composition's fault, logged once: the length, never the value —
			// the misconfiguration this catches is a middleware handing over an
			// e-mail or a username.
			deps.logger.error(
				{ site: "registration_verify", byteLength: userIdByteLength },
				"webauthn_subject_user_handle_invalid",
			);
			res.status(500).json({
				error: "server_error",
				error_description:
					"webauthnSubject.userId must be 1-64 bytes per WebAuthn section 5.4.3 (opaque user-handle)",
			});
			return;
		}

		// Validate request body (nickname + response shape; userId in body is ignored).
		const parsed = bodySchema.safeParse(req.body);
		if (!parsed.success) {
			res.status(400).json({ error: "invalid_request", details: parsed.error.issues });
			return;
		}

		const { response, nickname } = parsed.data;

		// Consume the single-use challenge atomically via ChallengeCeremony, which
		// needs the value. The options endpoint stored SimpleWebAuthn's base64url
		// `options.challenge`; the client returns it inside clientDataJSON, which is
		// base64url-encoded JSON under response.response (RegistrationResponseJSON:
		// { id, rawId, response: { clientDataJSON, ... }, ... }), so decode it
		// (base64url → JSON → challenge string).
		const innerResponse = (response as Record<string, unknown>).response;
		const clientDataJSONBase64 =
			innerResponse !== null &&
			typeof innerResponse === "object" &&
			"clientDataJSON" in (innerResponse as object)
				? (innerResponse as Record<string, unknown>).clientDataJSON
				: undefined;
		if (typeof clientDataJSONBase64 !== "string") {
			res
				.status(400)
				.json({ error: "invalid_request", details: "response.response.clientDataJSON missing" });
			return;
		}

		let challengeValue: string;
		try {
			const clientDataJSON = JSON.parse(
				Buffer.from(clientDataJSONBase64, "base64url").toString("utf8"),
			) as Record<string, unknown>;
			if (typeof clientDataJSON.challenge !== "string") {
				throw new Error("challenge missing");
			}
			challengeValue = clientDataJSON.challenge;
		} catch {
			res
				.status(400)
				.json({ error: "invalid_request", details: "response.response.clientDataJSON invalid" });
			return;
		}

		const ceremonyScope = `webauthn:registration:${userId}`;
		let outcome: Awaited<ReturnType<typeof deps.challengeCeremony.consume>>;
		try {
			outcome = await deps.challengeCeremony.consume(ceremonyScope, challengeValue);
		} catch (err) {
			refuseCeremonyStoreUnavailable(
				res,
				deps.logger,
				{ site: "registration_verify", store: "challenge_ceremony", step: "consume" },
				err,
			);
			return;
		}

		if (outcome.outcome !== "consumed") {
			// "unknown" = challenge never issued / already GC'd; "replayed" = replay attack.
			// Both cause rejection. No distinction exposed to the client (fail-closed).
			res.status(400).json({ error: "challenge_invalid" });
			return;
		}

		// Verify the attestation with multi-origin support. Pass userVerification
		// from config so SimpleWebAuthn enforces the UV flag when the deployment
		// sets userVerification = "required".
		const verification = await verifyWebAuthnAttestation({
			// biome-ignore lint/suspicious/noExplicitAny: RegistrationResponseJSON passthrough — validated by SimpleWebAuthn internally
			response: response as any,
			expectedChallenge: challengeValue,
			expectedRpId: deps.config.rpId,
			expectedOrigins: deps.config.origin,
			...(deps.config.topOrigin === undefined
				? {}
				: { expectedTopOrigins: deps.config.topOrigin }),
			userVerification: deps.config.userVerification,
		});

		if (!verification.ok) {
			res.status(400).json({ error: verification.reason });
			return;
		}

		// Atomic insert via registerCredential: the store contract guarantees N
		// concurrent inserts of the same credentialId give exactly one success and
		// N-1 throws, with no TOCTOU window between a find and a write.
		//
		// WebAuthn §5.1.3 credential IDs are globally unique by attacker-resistant
		// random generation, but the AS must not trust authenticator-supplied
		// uniqueness: a malicious authenticator returning a victim's credentialId,
		// a storage edge case, or a re-enrolment without deletion all collide, and
		// the store rejects each atomically. Same-user re-roll requires deleting
		// the prior credential first (no silent re-upsert). A collision is 400
		// (not 409), as validation errors are in this codebase. Any other adapter
		// error (e.g. transient Redis ECONNRESET) is the store's outage: 503,
		// logged once — never swallowed into a 200, and never a 500 the terminal
		// handler reports as unexpected.
		const { material } = verification;
		try {
			await deps.credentialStore.registerCredential({
				userId,
				credentialId: material.credentialId,
				publicKey: material.publicKey,
				signCount: material.signCount,
				transports: material.transports,
				backedUp: material.backedUp,
				createdAt: new Date(),
				...(nickname !== undefined ? { nickname } : {}),
			});
		} catch (err) {
			if (err instanceof WebAuthnCredentialStorageError && err.reason === "duplicate-credential") {
				res.status(400).json({
					error: "credential_id_conflict",
					error_description: "credential ID already registered",
				});
				return;
			}
			refuseCeremonyStoreUnavailable(
				res,
				deps.logger,
				{ site: "registration_verify", store: "webauthn_credential", step: "register" },
				err,
			);
			return;
		}

		res.status(200).json({
			credentialId: material.credentialId,
			transports: material.transports,
			backedUp: material.backedUp,
		});
	};
}
