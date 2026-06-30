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
import { DEFAULT_JWKS_PATH } from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response, Router } from "express";

type ExpressLike = {
	Router: () => Router;
	json: () => RequestHandler;
	urlencoded: (opts: { extended: boolean }) => RequestHandler;
};

export interface OidcConfigRouterOptions {
	issuer: string;
	signingAlgs: ReadonlyArray<string>;
	/**
	 * When true, advertise end_session_endpoint and backchannel/frontchannel logout_supported
	 * fields in the discovery response. Must be set explicitly — defaults to false so that
	 * callers who use this router directly (bypassing oauthModule) do not accidentally
	 * advertise logout support without mounting the logout route.
	 * oauthModule sets this to the computed `!!stores && !!issuer` expression.
	 */
	logoutSupported?: boolean;
	/**
	 * Absolute path appended to the issuer identifier (after trailing-slash
	 * trimming) to build the advertised `jwks_uri` — i.e. `jwks_uri =
	 * ${issuer}${jwksPath}`, so when the issuer itself has a path prefix the
	 * JWKS URI inherits it. Defaults to `/.well-known/jwks.json`. oauthModule
	 * resolves this via the shared core `resolveJwksPath` so the advertised
	 * URI matches the path the core `jwksModule` actually registers. Direct
	 * callers who publish JWKS at a non-default path MUST set this (an absolute
	 * path beginning with "/") so discovery does not advertise a dangling
	 * `jwks_uri`.
	 */
	jwksPath?: string;
}

export function createRouter(express: ExpressLike, opts: OidcConfigRouterOptions): Router {
	// Validate jwksPath at router-creation (boot) time so a misconfigured
	// direct caller fails fast rather than serving a discovery document whose
	// `jwks_uri` is malformed. oauthModule always passes a schema-validated,
	// `resolveJwksPath`-resolved value, so this never fires on the config path.
	const jwksPath = opts.jwksPath ?? DEFAULT_JWKS_PATH;
	if (!jwksPath.startsWith("/")) {
		throw new Error(
			`OIDC discovery: jwksPath must be an absolute path beginning with "/", got ${JSON.stringify(jwksPath)}`,
		);
	}
	const router = express.Router();

	router.get("/.well-known/openid-configuration", (_req: Request, res: Response) => {
		const iss = opts.issuer.replace(/\/+$/, "");
		return res.status(200).json({
			// Return the normalized issuer so it matches the `iss` claim minted
			// on tokens (both use trailing-slash-stripped form). Returning the
			// raw opts.issuer would cause RPs to reject tokens when iss differs
			// from discovery.issuer by a trailing slash.
			issuer: iss,
			authorization_endpoint: `${iss}/oauth/authorize`,
			token_endpoint: `${iss}/oauth/token`,
			userinfo_endpoint: `${iss}/oauth/userinfo`,
			jwks_uri: `${iss}${jwksPath}`,
			introspection_endpoint: `${iss}/oauth/introspect`,
			// Logout discovery fields are only advertised when the logout router is mounted.
			// opts.logoutSupported defaults to false (explicit opt-in); oauthModule sets it
			// to the computed !!stores && !!issuer expression. Callers who use createRouter
			// directly must pass logoutSupported: true explicitly.
			...(opts.logoutSupported === true
				? {
						end_session_endpoint: `${iss}/oauth/logout`,
						backchannel_logout_supported: true,
						backchannel_logout_session_supported: true,
						frontchannel_logout_supported: true,
						frontchannel_logout_session_supported: true,
					}
				: {}),
			response_types_supported: ["code"],
			subject_types_supported: ["public"],
			id_token_signing_alg_values_supported: [...opts.signingAlgs],
			// `groups` is supported by filterClaimsByScope (non-standard but opt-in)
			scopes_supported: ["openid", "profile", "email", "groups"],
			token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
			code_challenge_methods_supported: ["S256"],
		});
	});

	return router;
}
