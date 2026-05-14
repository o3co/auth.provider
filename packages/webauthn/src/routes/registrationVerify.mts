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
 * Security properties (spec §2.4):
 *   - Requires an authenticated subject on `req.webauthnSubject` (set by upstream
 *     session / bearer middleware). Returns 401 if absent.
 *   - Challenge is consumed atomically via ChallengeCeremony for the user-scoped
 *     namespace `webauthn:registration:${userId}`. Any outcome other than "consumed"
 *     (i.e. "unknown" or "replayed") immediately rejects with 400 challenge_invalid —
 *     replay rejection is the redemption primitive; no separate seen-challenge tracking.
 *   - userId is always taken from the authenticated session (req.webauthnSubject.userId),
 *     NOT from the request body — prevents victim-targeted enrollment.
 *   - nickname is validated: string, 1–64 characters (inclusive). Absent is valid;
 *     empty string is rejected. Limit: 64 chars (chosen to match common display-name
 *     field constraints; large enough for emoji and Unicode labels).
 *   - Multi-origin support: config.origin[] is passed to verifyWebAuthnAttestation (S7).
 *
 * NOT barrel-exported from the package index — internal to the webauthn module
 * until Task 31 wires the router.
 *
 * Cross-refs: Plan T28 / spec §2.4 / S7 multi-origin
 */

import {
	type ChallengeCeremony,
	WebAuthnCredentialStorageError,
	type WebAuthnCredentialStore,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import { z } from "zod";
import type { WebAuthnConfig } from "../config.mjs";
import { verifyWebAuthnAttestation } from "../internal/verification.mjs";

// ---------------------------------------------------------------------------
// Nickname validation constant
// ---------------------------------------------------------------------------

/**
 * Maximum length for a credential nickname, in Unicode code points (string .length
 * in JS measures UTF-16 code units; for BMP characters this is equivalent).
 *
 * 64 chars: large enough for typical display names and short emoji sequences;
 * small enough to avoid storage abuse. Consistent with common profile-field limits.
 */
const NICKNAME_MAX_LENGTH = 64;

// ---------------------------------------------------------------------------
// Request body schema
// ---------------------------------------------------------------------------

/**
 * Zod schema for the verify request body.
 *
 * `response` uses z.object().passthrough() because RegistrationResponseJSON is a
 * complex WebAuthn type. Shape validation is deferred to SimpleWebAuthn inside
 * verifyWebAuthnAttestation — the endpoint only needs `response` to be an object.
 *
 * `nickname` is optional; if present it must be a non-empty string of at most
 * NICKNAME_MAX_LENGTH characters.
 *
 * Any `userId` field in the body is intentionally not parsed — the endpoint reads
 * userId exclusively from req.webauthnSubject.
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
	// session/bearer auth resolved upstream — endpoint trusts req.webauthnSubject
}

// ---------------------------------------------------------------------------
// Handler factory
// ---------------------------------------------------------------------------

/**
 * Creates an Express RequestHandler for POST /oauth/webauthn/registration/verify.
 *
 * @param deps - Injected dependencies (config, challengeCeremony, credentialStore).
 * @returns RequestHandler suitable for mounting on an Express router.
 */
export function createRegistrationVerifyHandler(deps: RegistrationVerifyDeps): RequestHandler {
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

		// Validate request body (nickname + response shape; userId in body is ignored).
		const parsed = bodySchema.safeParse(req.body);
		if (!parsed.success) {
			res.status(400).json({ error: "invalid_request", details: parsed.error.issues });
			return;
		}

		const { response, nickname } = parsed.data;

		// §2.4: Consume the single-use challenge atomically via ChallengeCeremony.
		// The challenge value comes from the WebAuthn client response's clientDataJSON.
		// SimpleWebAuthn encodes the challenge as a base64url string inside clientDataJSON;
		// the stored challenge (issued in the options endpoint) is also base64url. We
		// extract it from the response object at runtime — it is present in
		// RegistrationResponseJSON as response.clientDataJSON (base64url JSON containing
		// { challenge: base64urlString }). However, the challenge key we stored at issue
		// time is the raw base64url from SimpleWebAuthn's generateRegistrationOptions
		// output, which SimpleWebAuthn also uses as expectedChallenge internally.
		//
		// Ceremony lookup: the challenge stored in the options endpoint is the
		// base64url string (`options.challenge`). We need to look up the same value here.
		// The client returns it inside clientDataJSON — but we don't decode clientDataJSON
		// here; instead, we look up the *live* challenge by fetching it from the store
		// via a two-step approach: find → consume. ChallengeCeremony.consume(scope, value)
		// needs the value.
		//
		// The SimpleWebAuthn RegistrationResponseJSON does NOT expose the decoded challenge
		// as a top-level field — clientDataJSON is still base64url-encoded JSON. We must
		// decode it to get the challenge string that matches what was stored.
		//
		// Decode clientDataJSON (base64url → JSON → challenge string).
		// RegistrationResponseJSON structure: { id, rawId, response: { clientDataJSON, ... }, ... }
		// clientDataJSON lives one level deeper under response.response, not at response.clientDataJSON.
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
				.json({ error: "invalid_request", details: "response.clientDataJSON invalid" });
			return;
		}

		const ceremonyScope = `webauthn:registration:${userId}`;
		const outcome = await deps.challengeCeremony.consume(ceremonyScope, challengeValue);

		if (outcome.outcome !== "consumed") {
			// "unknown" = challenge never issued / already GC'd; "replayed" = replay attack.
			// Both cause rejection. No distinction exposed to the client (fail-closed).
			res.status(400).json({ error: "challenge_invalid" });
			return;
		}

		// §2.4 §S7: Verify the attestation with multi-origin support.
		// Pass userVerification from config so SimpleWebAuthn enforces the UV flag
		// when the deployment sets userVerification = "required".
		// Cross-refs: Codex Round 2 P1-1 / spec §2.5
		const verification = await verifyWebAuthnAttestation({
			// biome-ignore lint/suspicious/noExplicitAny: RegistrationResponseJSON passthrough — validated by SimpleWebAuthn internally
			response: response as any,
			expectedChallenge: challengeValue,
			expectedRpId: deps.config.rpId,
			expectedOrigins: deps.config.origin,
			userVerification: deps.config.userVerification,
		});

		if (!verification.ok) {
			res.status(400).json({ error: verification.reason });
			return;
		}

		// §2.4 / WebAuthn §5.1.3 / Codex Round 5 P2: atomic insert via registerCredential.
		// The store contract guarantees N concurrent inserts of the same credentialId
		// result in exactly one success and N-1 throws — no TOCTOU window between a
		// find check and a write.
		//
		// Defense-in-depth: WebAuthn §5.1.3 specifies credential IDs as globally unique
		// by attacker-resistant random generation, but the AS must not trust
		// authenticator-supplied uniqueness. A malicious authenticator returning a
		// credentialId matching a victim's existing record, a storage edge case, or a
		// user re-enrolling without deletion all produce the same collision; the store
		// rejects all of them atomically.
		//
		// Same-user re-roll requires explicit deletion of the prior credential first
		// (no silent re-upsert). Returns 400 (not 409) per OAuth-style endpoint
		// convention — validation errors use 400 in this codebase. Any non-duplicate
		// adapter error (e.g. transient Redis ECONNRESET) is rethrown to Express 5's
		// default async error handler → 500, never silently swallowed.
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
			throw err;
		}

		res.status(200).json({
			credentialId: material.credentialId,
			transports: material.transports,
			backedUp: material.backedUp,
		});
	};
}
