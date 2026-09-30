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
 * Who may ask `/oauth/introspect`: a caller whose credential is its own
 * access token (Bearer or DPoP) may ask about that token alone, once it
 * verifies; any other caller must pass the client authentication the router
 * built for this endpoint.
 */

import {
	type AccessTokenDenylist,
	type AuditSink,
	isVerificationUnavailable,
	JwtVerificationError,
	type KeyStore,
	type Logger,
	type SubjectRevocation,
	verifyJwt,
} from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import { parseAccessTokenHeader } from "../accessTokenHeader.mjs";
import { introspectionOutageAnswers } from "./introspectUnavailable.mjs";

export const createIntrospectCallerCheck = ({
	keyStore,
	canonicalIssuer,
	legacyTypAccept: legacyTypAcceptOpt,
	accessTokenDenylist,
	subjectRevocation,
	introspectClientAuthMw,
	auditSink,
	logger,
}: {
	readonly keyStore: KeyStore;
	readonly canonicalIssuer: string;
	readonly legacyTypAccept: boolean | undefined;
	readonly accessTokenDenylist: AccessTokenDenylist | undefined;
	readonly subjectRevocation: SubjectRevocation | undefined;
	/** What a caller without its own access token as the credential must pass. */
	readonly introspectClientAuthMw: RequestHandler;
	readonly auditSink: AuditSink | undefined;
	readonly logger: Logger;
}): RequestHandler => {
	const { answerIntrospectionUnavailable } = introspectionOutageAnswers({ auditSink, logger });
	return async (req: Request, res: Response, next) => {
		// Bearer (RFC 6750 §2.1) or DPoP (RFC 9449 §7.1) — the caller's own
		// access token used as the introspection credential. Which scheme a
		// given token may use is enforced against its `cnf` by
		// `protectedResourceBindingMw` upstream.
		const credentialToken = parseAccessTokenHeader(req.headers.authorization);
		if (credentialToken !== null) {
			// Self-introspection pattern: RFC 7662 requires a valid credential to call introspect.
			// When the caller uses their own access token as that credential, the token in the
			// request body must match the one in the Authorization header. If they differ, return
			// inactive (not 403) per RFC 7662 §2.2 — the server must not reveal whether the
			// token exists.
			if (req.body.token !== credentialToken) {
				return res.status(200).json({ active: false });
			}
			try {
				// Token-as-credential self-intro — calling-client identity is not
				// established (introspectClientAuthMw is skipped on this
				// fall-through path), so audience pinning is deferred. alg / iss /
				// typ + signature are still pinned by the central verifier, and
				// the denylist is consulted so revoked ATs cannot serve as their
				// own introspection credential.
				await verifyJwt(credentialToken, keyStore, {
					type: "access_token",
					expectedIssuer: canonicalIssuer,
					legacyTypAccept: legacyTypAcceptOpt ?? false,
					// Token-accepting surface — forward what the composition
					// wired, jti denylist and subject watermark both.
					revocation: { denylist: accessTokenDenylist, subjectRevocation },
					logger,
				});
				return next();
			} catch (cause) {
				// A keystore or revocation store that could not answer says
				// nothing about the token: 503, never `active: false` — see
				// `answerIntrospectionUnavailable` (`./introspectUnavailable.mts`).
				if (isVerificationUnavailable(cause)) {
					return answerIntrospectionUnavailable(req, res, cause);
				}
				// Distinguish non-access-token typ rejections so SIEM
				// can spot a refresh / id token presented as a Bearer
				// credential. RFC 7662 §2.2 forbids leaking the typ to the
				// caller — the audit log carries the signal instead.
				// Other JwtVerificationError reasons (alg / iss / aud /
				// signature / expired / kid_*) already emit
				// `jwt_verify_rejected` from the central verifier — SIEM
				// rule authors should NOT double-count by also matching
				// `introspect_non_access_token` for those reasons.
				if (cause instanceof JwtVerificationError && cause.reason === "typ") {
					logger.warn(
						{ reason: "non_access_token", site: "introspect_bearer" },
						"introspect_non_access_token",
					);
				}
				return res.status(200).json({ active: false });
			}
		}
		return introspectClientAuthMw(req, res, next);
	};
};
