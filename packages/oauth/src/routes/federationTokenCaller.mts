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
 * Who is calling: the access token in the Authorization header, verified as
 * this issuer's `at+jwt`, and the claims the route acts on. Every refusal is
 * `401 invalid_token` with its challenge, but a keystore or revocation-store
 * outage, which is `503`.
 */

import {
	isVerificationUnavailable,
	JwtVerificationError,
	loggableError,
	verifyJwt,
} from "@o3co/auth-provider-core";
import { parseAccessTokenHeader } from "../accessTokenHeader.mjs";
import { refuseVerificationUnavailable } from "../verificationUnavailable.mjs";
import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";

/**
 * Steps 1 to 4: the token, its verification, and `family_id`, `sid` and
 * `azp`, each required. Returns the caller, or `null` once answered.
 */
export const identifyCaller = async (
	ctx: FederationTokenContext,
): Promise<FederationTokenCaller | null> => {
	const { opts, req, res, federation, logger } = ctx;

	// Step 1: Extract the access token from the Authorization header —
	// Bearer (RFC 6750 §2.1) or DPoP (RFC 9449 §7.1). Scheme-vs-`cnf`
	// agreement is enforced by `protectedResourceBindingMw` upstream.
	const token = parseAccessTokenHeader(req.headers.authorization);
	if (token === null) {
		res.setHeader(
			"WWW-Authenticate",
			'Bearer error="invalid_token", error_description="missing access token"',
		);
		res.status(401).json({ error: "invalid_token", error_description: "missing access token" });
		return null;
	}

	// Steps 2 + 3: alg / iss / typ (at+jwt) and signature, pinned by the
	// verifier. Audience is not checked: the calling client is not
	// separately authenticated (logged as `jwt_verify_aud_skipped`).
	let payload: Record<string, unknown>;
	try {
		const verified = await verifyJwt(token, opts.keyStore, {
			type: "access_token",
			expectedIssuer: opts.issuer ?? "",
			// A token-accepting surface: forward both the jti denylist and the
			// subject watermark.
			revocation: {
				denylist: opts.accessTokenDenylist,
				subjectRevocation: opts.subjectRevocation,
			},
			logger: opts.logger,
		});
		payload = verified.payload as Record<string, unknown>;
	} catch (error) {
		// The keystore or a revocation store did not answer: the server's
		// outage, not a verdict on the token (`isVerificationUnavailable`).
		if (isVerificationUnavailable(error)) {
			refuseVerificationUnavailable(res, error, logger, "federation_token");
			return null;
		}
		// Log the verifier's reason only: its message quotes token content,
		// and it has already logged `jwt_verify_rejected`.
		const verdict = error instanceof JwtVerificationError ? error.reason : undefined;
		logger.warn(
			verdict === undefined
				? { federation, err: loggableError(error) }
				: { federation, reason: verdict },
			"federation_token_jwt_verify_failed",
		);
		res.setHeader(
			"WWW-Authenticate",
			'Bearer error="invalid_token", error_description="invalid token"',
		);
		res.status(401).json({
			error: "invalid_token",
			error_description: "invalid token",
		});
		return null;
	}

	// Step 4: Extract family_id, sid, azp from payload.
	const familyId = typeof payload.family_id === "string" ? payload.family_id : null;
	const sid = typeof payload.sid === "string" ? payload.sid : null;
	const azp = typeof payload.azp === "string" ? payload.azp : null;
	const sub = typeof payload.sub === "string" ? payload.sub : null;

	if (!familyId) {
		res.setHeader(
			"WWW-Authenticate",
			'Bearer error="invalid_token", error_description="missing family_id claim"',
		);
		res.status(401).json({ error: "invalid_token", error_description: "missing family_id claim" });
		return null;
	}
	if (!sid) {
		res.setHeader(
			"WWW-Authenticate",
			'Bearer error="invalid_token", error_description="missing sid claim"',
		);
		res.status(401).json({ error: "invalid_token", error_description: "missing sid claim" });
		return null;
	}
	if (!azp) {
		res.setHeader(
			"WWW-Authenticate",
			'Bearer error="invalid_token", error_description="missing azp claim"',
		);
		res.status(401).json({ error: "invalid_token", error_description: "missing azp claim" });
		return null;
	}
	return { familyId, sid, azp, sub };
};
