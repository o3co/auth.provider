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
import type { Request, RequestHandler, Response, Router } from "express";

type ExpressLike = {
	Router: () => Router;
	json: () => RequestHandler;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

export interface OidcConfigRouterOptions {
	issuer: string;
	signingAlgs: ReadonlyArray<string>;
}

export function createRouter(express: ExpressLike, opts: OidcConfigRouterOptions): Router {
	const router = express.Router();

	router.get("/.well-known/openid-configuration", (_req: Request, res: Response) => {
		const iss = opts.issuer.replace(/\/+$/, "");
		// JWKS is not served for symmetric-only deployments (HS256): the
		// public-key set is empty, so advertising jwks_uri would point
		// consumers at a 404. Only include jwks_uri when at least one
		// asymmetric alg is configured.
		const hasAsymmetricAlg = opts.signingAlgs.some((alg) => alg !== "HS256");
		return res.status(200).json({
			issuer: opts.issuer,
			authorization_endpoint: `${iss}/oauth/authorize`,
			token_endpoint: `${iss}/oauth/token`,
			userinfo_endpoint: `${iss}/oauth/userinfo`,
			...(hasAsymmetricAlg ? { jwks_uri: `${iss}/.well-known/jwks.json` } : {}),
			introspection_endpoint: `${iss}/oauth/introspect`,
			response_types_supported: ["code"],
			subject_types_supported: ["public"],
			id_token_signing_alg_values_supported: [...opts.signingAlgs],
			// `groups` is supported by filterClaimsByScope (non-standard but opt-in)
			scopes_supported: ["openid", "profile", "email", "groups"],
			token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
			code_challenge_methods_supported: ["S256"],
			// OUT of F-4 scope: revocation_endpoint, end_session_endpoint,
			// backchannel_logout_supported, frontchannel_logout_supported —
			// F-5 will add them when the corresponding routes exist.
		});
	});

	return router;
}
