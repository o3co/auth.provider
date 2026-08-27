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
 * Sender-constraint enforcement for **protected resources** — the RFC 9449
 * §7.1 / RFC 8705 §3 counterpart to `tokenBindingMw`.
 *
 * `tokenBindingMw` runs at `/oauth/token` and answers "what binding is this
 * client presenting?" so a grant can stamp it into the issued token's `cnf`.
 * It says nothing about later requests. Without the middleware in this file a
 * `cnf`-bearing access token is accepted at `/oauth/userinfo`, the federation
 * token endpoint, `/oauth/logout`, and bearer self-introspection as an
 * ordinary Bearer JWT — so a stolen DPoP- or mTLS-bound token replays
 * unbound, which is the whole point of binding it (issue #264).
 *
 * What it enforces, for a token that carries a `cnf`:
 *
 *   1. The wire scheme matches the binding. `cnf.jkt` REQUIRES the `DPoP`
 *      auth scheme (RFC 9449 §7.1 — a DPoP-bound token presented as a
 *      Bearer token must be refused); `cnf["x5t#S256"]` keeps `Bearer`,
 *      because RFC 8705 does not redefine the wire-level token type.
 *   2. A mechanism *of the kind that owns that `cnf` variant* validated the
 *      material on this request, and produced the same confirmation value.
 *
 * Deliberately NOT layered on `tokenBindingMw`: that middleware resolves
 * competing mechanisms by `DispatchPolicy` and answers with 400 +
 * `errorEnvelope`. Here the token already names its binding, so there is
 * nothing to arbitrate — the answer must come from the mechanism the token
 * points at — and a protected resource owes RFC 6750 §3 a 401 with a
 * `WWW-Authenticate` challenge.
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

export interface ProtectedResourceBindingOptions {
	/**
	 * The same mechanisms `tokenBindingMw` is composed from. MAY be empty:
	 * a deployment with no mechanisms still has to refuse `cnf`-bearing
	 * tokens minted before the mechanism was removed, so an empty list is a
	 * meaningful configuration rather than a reason to skip the middleware.
	 */
	readonly mechanisms: readonly TokenBindingMechanism[];
	readonly logger?: Logger;
}

export const protectedResourceBindingMw = ({
	mechanisms,
	logger,
}: ProtectedResourceBindingOptions): RequestHandler => {
	return async (req, res, next) => {
		// Anything that is not an access-token scheme belongs to another
		// authentication surface — `Basic` client auth on the introspection
		// endpoint is the case that actually occurs — and is not ours to judge.
		const authorization = parseAccessTokenAuthorization(req.headers.authorization);
		if (authorization === null) {
			next();
			return;
		}
		const { scheme, token: accessToken } = authorization;

		// Claims are read WITHOUT verifying the signature; the endpoint
		// downstream still runs the full `verifyJwt`. That is sound because the
		// two reads cannot disagree — `decodeJwt` is the same primitive
		// `jwt/verify.mts` uses, over the same bytes — so a token whose `cnf`
		// is enforced here is the same token whose signature is checked there.
		// A token that fails to decode is left to the endpoint to reject, which
		// keeps the "invalid token" response in one place.
		let claims: Record<string, unknown>;
		try {
			claims = decodeJwt(accessToken) as Record<string, unknown>;
		} catch {
			next();
			return;
		}

		// Classify the token's `cnf` before any mechanism runs: `binding` is
		// still unresolved here, so the match can only be `unbound`,
		// `compound`, or `no-proof` — the latter meaning "bound by `member`,
		// proof still to be collected below".
		const match = matchConfirmation(claims.cnf, null);
		if (match.status === "unbound") {
			// Unbound token (or a junk `cnf` that names no binding). Nothing to
			// enforce — an unbound token was never sender-constrained, and the
			// endpoint's own authorization checks still apply.
			next();
			return;
		}

		const reject = (reason: string, challenge: string, description: string): void => {
			logger?.warn(
				{ reason, scheme, site: "protected_resource_binding" },
				"sender_constraint_rejected",
			);
			res.setHeader("WWW-Authenticate", `${challenge} error="invalid_token"`);
			// RFC 6750 §3.1 gives one code for every token-level failure. The
			// granular reason goes to the audit log above and never to the
			// caller: telling an attacker holding a stolen bound token whether
			// they got the scheme, the proof, or the key wrong hands them a
			// tuning oracle.
			res.status(401).json(errorEnvelope("invalid_token", description));
		};

		if (match.status === "compound") {
			// This AS mints exactly one mechanism's confirmation per token, so a
			// compound `cnf` means a forged token or an AS bug. Refuse rather
			// than pick a winner — the same call `grants/refreshToken.mts` and
			// the introspection handler already make.
			reject("compound_cnf", "Bearer", "access token carries an ambiguous compound cnf binding");
			return;
		}

		const { member } = match;
		const profile = BINDING_PROFILES[member];

		if (scheme !== profile.scheme) {
			// The #264 replay: a DPoP-bound token handed over as `Bearer`.
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
				logger?.warn(
					{ mechanism: mechanism.kind, err },
					"protected_resource_binding_proof_invalid",
				);
				reject("proof_invalid", profile.challenge, "presented proof-of-possession is invalid");
				return;
			}
			if (candidate !== null && matchConfirmation(claims.cnf, candidate).status === "satisfied") {
				binding = candidate;
				break;
			}
		}

		if (binding === null) {
			// Covers all three ways the proof can fail to arrive: the mechanism
			// is not installed (a deployment that dropped the module while bound
			// tokens are still live), no material was presented, or the material
			// proved possession of a different key or certificate. Each is a
			// stolen-token replay from the resource's point of view. (For why
			// the thumbprint comparison is a plain `!==`, see
			// `grants/confirmationMatch.mts`.)
			reject(
				"no_matching_binding",
				profile.challenge,
				"access token is sender-constrained and no matching proof-of-possession was presented",
			);
			return;
		}

		req.tokenBinding = binding;
		next();
	};
};
