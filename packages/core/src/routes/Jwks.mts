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
import type { Request, Response, Router } from "express";
import { exportJWK } from "jose";
import { DEFAULT_JWKS_CACHE_MAX_AGE } from "../jwks/cache.mjs";
import { DEFAULT_JWKS_PATH } from "../jwks/path.mjs";
import type { KeyStore } from "../keys/KeyStore.mjs";

/** Options for {@link createRouter}. */
export interface JwksRouterOptions {
	/**
	 * Absolute path the router registers internally. Defaults to
	 * {@link DEFAULT_JWKS_PATH}. Callers honoring the `oauth.jwt.jwksPath`
	 * override resolve it via `resolveJwksPath` and pass the result here so
	 * the registered path matches the advertised `jwks_uri`.
	 */
	path?: string;
	/**
	 * `Cache-Control: public, max-age=<N>` lifetime in seconds for the JWKS
	 * response. Defaults to {@link DEFAULT_JWKS_CACHE_MAX_AGE}. Callers
	 * honoring `oauth.jwt.jwksCacheMaxAge` resolve it via
	 * `resolveJwksCacheMaxAge`. Keep well below the key-overlap window so a
	 * freshly-rotated kid propagates to caching verifiers in time.
	 */
	cacheMaxAgeSeconds?: number;
}

/**
 * Build the JWKS publishing Router. The router registers `path` as an
 * **absolute** path internally, so the effective endpoint is the router's
 * mount point + `path`. Mount at the application root (`app.use(createRouter(
 * express, keyStore))`) for the common case. Prefix-mounting (e.g.
 * `app.use("/auth", createRouter(...))`) is valid only when the advertised
 * `jwks_uri` carries the same base path — typically because the issuer
 * identifier itself has that prefix (`jwks_uri = ${issuer}${path}`). If the
 * mount prefix and the issuer prefix disagree, discovery advertises a
 * `jwks_uri` that does not resolve. (The core `jwksModule` mounts at "/" and
 * relies on the issuer prefix to carry any base path.)
 *
 * The response carries `Cache-Control: public, max-age=<cacheMaxAgeSeconds>`
 * (JWKS is public data and the most-polled verifier endpoint).
 *
 * Direct callers bypass the config schema, so `path` and `cacheMaxAgeSeconds`
 * are validated here and the factory throws on misconfiguration (a non-
 * absolute path or a negative / non-integer cache age) — failing fast at
 * boot rather than registering an unexpected route or emitting an invalid
 * `Cache-Control` header.
 */
export const createRouter = (
	express: { Router: () => Router },
	keyStore: KeyStore,
	opts: JwksRouterOptions = {},
): Router => {
	const path = opts.path ?? DEFAULT_JWKS_PATH;
	if (!path.startsWith("/")) {
		throw new Error(
			`createJwksRouter: path must be an absolute path beginning with "/", got ${JSON.stringify(path)}`,
		);
	}
	const cacheMaxAgeSeconds = opts.cacheMaxAgeSeconds ?? DEFAULT_JWKS_CACHE_MAX_AGE;
	if (!Number.isInteger(cacheMaxAgeSeconds) || cacheMaxAgeSeconds < 0) {
		throw new Error(
			`createJwksRouter: cacheMaxAgeSeconds must be a non-negative integer, got ${cacheMaxAgeSeconds}`,
		);
	}
	const router = express.Router();

	const cacheControl = `public, max-age=${cacheMaxAgeSeconds}`;

	router.get(path, async (_req: Request, res: Response) => {
		if (keyStore.algorithm === "HS256") {
			// Set Cache-Control only on the SUCCESS path. If we set it up-front
			// and `getVerificationKeys()`/`exportJWK()` then threw (e.g. a remote
			// KMS-backed keystore outage), Express would emit a 5xx with the
			// header still attached, and an explicit `public, max-age` makes that
			// transient error cacheable by shared caches/CDNs for the full
			// lifetime — turning a brief outage into a stuck JWKS failure.
			res.setHeader("Cache-Control", cacheControl);
			return res.json({ keys: [] });
		}
		const managedKeys = await keyStore.getVerificationKeys();
		const keys = await Promise.all(
			managedKeys.map(async (mk) => {
				const jwk = await exportJWK(mk.publicKey);
				return { ...jwk, kid: mk.kid, use: "sig", alg: keyStore.algorithm };
			}),
		);
		// Header set only after key export succeeded (see HS256 branch note).
		res.setHeader("Cache-Control", cacheControl);
		return res.json({ keys });
	});

	return router;
};
