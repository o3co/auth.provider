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
 */

/**
 * Sender-constraint enforcement for **protected resources**: the RFC 9449 §7.1
 * / RFC 8705 §3 counterpart to `tokenBindingMw`, which only binds tokens at
 * `/oauth/token`. Without it, a `cnf`-bearing access token would be accepted as
 * an ordinary Bearer JWT at `/oauth/userinfo`, the federation token endpoint,
 * `/oauth/logout` and bearer self-introspection, so a stolen DPoP- or
 * mTLS-bound token would replay unbound.
 *
 * For a token carrying a `cnf`:
 *
 *   1. The wire scheme matches the binding: `cnf.jkt` requires `DPoP` (RFC 9449
 *      §7.1); `cnf["x5t#S256"]` keeps `Bearer` (RFC 8705 does not redefine the
 *      token type).
 *   2. A mechanism *of the kind that owns that `cnf` variant* validated the
 *      material on this request and produced the same confirmation value.
 *
 * Not layered on `tokenBindingMw`, which arbitrates mechanisms by
 * `DispatchPolicy` and answers 400: here the token names its binding, and a
 * protected resource owes RFC 6750 §3 a 401 with a `WWW-Authenticate`
 * challenge. A mechanism outage (`TokenBindingRefusal.unavailable`) is `503`
 * with no challenge, since the credential is not what failed.
 */

import type { Request, RequestHandler } from "express";
import { decodeJwt } from "jose";
import { parseAccessTokenAuthorization } from "../accessTokenHeader.mjs";
import { errorEnvelope } from "../errors/envelope.mjs";
import { BINDING_PROFILES, matchConfirmation } from "../grants/confirmationMatch.mjs";
import type { TokenBinding } from "../grants/tokenBinding.mjs";
import type { Logger } from "../logging/Logger.mjs";
import type { TokenBindingMechanism } from "./tokenBinding.mjs";

import "./express.mjs"; // ensure ambient Express.Request augmentation is loaded
import {
	applyResponseHeaders,
	oauthErrorCodeOf,
	retryInstructionOf,
	unavailableLogFields,
	unavailableOf,
	verdictLogFields,
} from "./_responseHeaders.mjs";

export interface ProtectedResourceBindingOptions {
	/**
	 * The same mechanisms `tokenBindingMw` is composed from. May be empty: a
	 * deployment with none must still refuse `cnf`-bearing tokens minted before
	 * a mechanism was removed.
	 */
	readonly mechanisms: readonly TokenBindingMechanism[];
	readonly logger?: Logger;
}

export const protectedResourceBindingMw = ({
	mechanisms,
	logger,
}: ProtectedResourceBindingOptions): RequestHandler => {
	return async (req, res, next) => {
		// Other schemes belong to another authentication surface (in practice
		// `Basic` client auth on the introspection endpoint).
		const authorization = parseAccessTokenAuthorization(req.headers.authorization);
		if (authorization === null) {
			next();
			return;
		}
		const { scheme, token: accessToken } = authorization;

		// Claims are read WITHOUT verifying the signature; the endpoint still
		// runs `verifyJwt`. Sound because both reads use `decodeJwt` over the same
		// bytes, so the token whose `cnf` is enforced here is the one whose
		// signature is checked there. A token that fails to decode is left to the
		// endpoint, keeping the "invalid token" response in one place.
		let claims: Record<string, unknown>;
		try {
			claims = decodeJwt(accessToken) as Record<string, unknown>;
		} catch {
			next();
			return;
		}

		// Classify `cnf` before any mechanism runs: with no binding yet the match
		// is `unbound`, `compound`, or `no-proof` (bound by `member`, proof to
		// be collected below).
		const match = matchConfirmation(claims.cnf, null);
		if (match.status === "unbound") {
			// Unbound (or a junk `cnf` naming no binding): nothing to enforce; the
			// endpoint's own authorization checks still apply.
			next();
			return;
		}

		const reject = (rejection: string, challenge: string, description: string): void => {
			// `rejection`, not `reason`: the verdict line written beside a
			// `proof_invalid` uses `reason` for the mechanism's own name for the
			// refused proof.
			logger?.warn(
				{ rejection, scheme, site: "protected_resource_binding" },
				"sender_constraint_rejected",
			);
			res.setHeader("WWW-Authenticate", `${challenge} error="invalid_token"`);
			// RFC 6750 §3.1 gives one code for every token-level failure. The
			// granular reason goes only to the log: telling the holder of a stolen
			// bound token whether the scheme, the proof or the key was wrong hands
			// them a tuning oracle.
			res.status(401).json(errorEnvelope("invalid_token", description));
		};

		if (match.status === "compound") {
			// This AS mints one mechanism's confirmation per token, so a compound
			// `cnf` means a forged token or an AS bug. Refuse rather than pick a
			// winner, as `grants/refreshToken.mts` and introspection do.
			reject("compound_cnf", "Bearer", "access token carries an ambiguous compound cnf binding");
			return;
		}

		const { member } = match;
		const profile = BINDING_PROFILES[member];

		if (scheme !== profile.scheme) {
			// The replay this guards against: a DPoP-bound token sent as `Bearer`.
			reject(
				"scheme_mismatch",
				profile.challenge,
				`a token bound by ${member} must be presented using the ${profile.challenge} scheme`,
			);
			return;
		}

		const owning = mechanisms.filter((mechanism) => mechanism.kind === profile.kind);
		let binding: TokenBinding | null = null;
		for (const mechanism of owning) {
			let candidate: TokenBinding | null;
			try {
				candidate = await mechanism.extract(req as Request, { boundAccessToken: accessToken });
			} catch (err) {
				const code = oauthErrorCodeOf(err);
				const unavailable = unavailableOf(err);
				if (unavailable !== undefined && code !== undefined) {
					// No verdict: refused as the server's fault, with no challenge.
					// `401 invalid_token` would tell the client to replace a token that
					// is fine, and the refresh would meet the same outage. This layer
					// answers the 503, so it writes the outage's one log line.
					logger?.error(
						{ mechanism: mechanism.kind, code, ...unavailableLogFields(err) },
						"protected_resource_binding_unavailable",
					);
					res.status(503).json(errorEnvelope(code, unavailable));
					return;
				}
				// The same verdict line the token endpoint writes.
				logger?.warn(
					{
						mechanism: mechanism.kind,
						...(code !== undefined ? { code } : {}),
						...verdictLogFields(err),
					},
					"protected_resource_binding_proof_invalid",
				);
				const retryInstruction = retryInstructionOf(err);
				if (retryInstruction !== undefined && code !== undefined) {
					// A retry instruction, not a verdict (RFC 9449 §9's nonce
					// challenge): answer with the error the challenge names and the
					// headers to retry with.
					applyResponseHeaders(res, err);
					res.setHeader("WWW-Authenticate", `${profile.challenge} error="${code}"`);
					res.status(401).json(errorEnvelope(code, retryInstruction));
					return;
				}
				reject("proof_invalid", profile.challenge, "presented proof-of-possession is invalid");
				return;
			}
			if (candidate !== null && matchConfirmation(claims.cnf, candidate).status === "satisfied") {
				binding = candidate;
				break;
			}
		}

		if (binding === null) {
			// The mechanism is not installed (dropped while bound tokens are still
			// live), no material was presented, or it proved a different key or
			// certificate. Each is a stolen-token replay to the resource. (Why the
			// thumbprint comparison is a plain `!==`: `grants/confirmationMatch.mts`.)
			reject(
				"no_matching_binding",
				profile.challenge,
				"access token is sender-constrained and no matching proof-of-possession was presented",
			);
			return;
		}

		applyResponseHeaders(res, binding);
		req.tokenBinding = binding;
		next();
	};
};
