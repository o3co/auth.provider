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
import { errorEnvelope } from "../errors/envelope.mjs";
import type { Confirmation } from "../grants/confirmation.mjs";
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

/**
 * The auth scheme a token bound by each `cnf` variant must be presented
 * under, and the mechanism `kind` that owns that variant.
 *
 * Both halves are core vocabulary: core owns the `Confirmation` union
 * (`grants/confirmation.mts`), and the spec makes adding a variant a core
 * semver-minor change — so the mapping lives with the union rather than
 * being negotiated with each mechanism package. Gating on `kind` (rather
 * than on the confirmation's shape alone) is the same stance
 * `grants/refreshToken.mts` takes: `Confirmation` is mechanism-extensible,
 * so a third-party mechanism could emit `{ jkt }` without ever validating a
 * DPoP proof, and shape-matching alone would hand it a bound token.
 */
const BINDING_PROFILES = {
	jkt: { kind: "dpop", scheme: "dpop", challenge: "DPoP" },
	"x5t#S256": { kind: "mtls", scheme: "bearer", challenge: "Bearer" },
} as const satisfies Record<string, { kind: string; scheme: string; challenge: string }>;

type ConfirmationMember = keyof typeof BINDING_PROFILES;

const CONFIRMATION_MEMBERS = Object.keys(BINDING_PROFILES) as readonly ConfirmationMember[];

/** Schemes that carry an access token, lowercased for comparison. */
const TOKEN_SCHEMES: ReadonlySet<string> = new Set(["bearer", "dpop"]);

const readMember = (
	cnf: Record<string, unknown>,
	member: ConfirmationMember,
): string | undefined => {
	const value = cnf[member];
	return typeof value === "string" && value.length > 0 ? value : undefined;
};

const confirmationValue = (
	confirmation: Confirmation,
	member: ConfirmationMember,
): string | undefined => readMember(confirmation as unknown as Record<string, unknown>, member);

export const protectedResourceBindingMw = ({
	mechanisms,
	logger,
}: ProtectedResourceBindingOptions): RequestHandler => {
	return async (req, res, next) => {
		const authorization = req.headers.authorization;
		if (authorization === undefined) {
			next();
			return;
		}

		const separator = authorization.indexOf(" ");
		if (separator === -1) {
			next();
			return;
		}
		const scheme = authorization.slice(0, separator).toLowerCase();
		const accessToken = authorization.slice(separator + 1).trim();
		// Anything that is not an access-token scheme belongs to another
		// authentication surface — `Basic` client auth on the introspection
		// endpoint is the case that actually occurs — and is not ours to judge.
		if (!TOKEN_SCHEMES.has(scheme) || accessToken === "") {
			next();
			return;
		}

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

		const cnf = claims.cnf;
		if (!cnf || typeof cnf !== "object" || Array.isArray(cnf)) {
			// Unbound token (or a junk `cnf` that names no binding). Nothing to
			// enforce — an unbound token was never sender-constrained, and the
			// endpoint's own authorization checks still apply.
			next();
			return;
		}

		const present = CONFIRMATION_MEMBERS.filter(
			(member) => readMember(cnf as Record<string, unknown>, member) !== undefined,
		);

		if (present.length === 0) {
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

		if (present.length > 1) {
			// This AS mints exactly one mechanism's confirmation per token, so a
			// compound `cnf` means a forged token or an AS bug. Refuse rather
			// than pick a winner — the same call `grants/refreshToken.mts` and
			// the introspection handler already make.
			reject("compound_cnf", "Bearer", "access token carries an ambiguous compound cnf binding");
			return;
		}

		const member = present[0] as ConfirmationMember;
		const expected = readMember(cnf as Record<string, unknown>, member) as string;
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
			if (candidate !== null && confirmationValue(candidate.confirmation, member) === expected) {
				binding = candidate;
				break;
			}
		}

		if (binding === null) {
			// Covers all three ways the proof can fail to arrive: the mechanism
			// is not installed (a deployment that dropped the module while bound
			// tokens are still live), no material was presented, or the material
			// proved possession of a different key or certificate. Each is a
			// stolen-token replay from the resource's point of view.
			//
			// Plain `!==` on the thumbprint (inside the loop above): `jkt` is a
			// SHA-256 digest of a *public* key and `x5t#S256` of a certificate
			// the client just presented — neither is secret, so there is no
			// material a timing side-channel could leak that the caller does not
			// already hold. Mirrors `grants/refreshToken.mts`.
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
