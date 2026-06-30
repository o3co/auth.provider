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
import { DEFAULT_JWKS_PATH } from "../jwks/path.mjs";
import type { KeyStore } from "../keys/KeyStore.mjs";

/**
 * Build the JWKS publishing Router. The router registers `path` as an
 * **absolute** path internally, so consumers MUST mount the router at the
 * application root (`app.use(createRouter(express, keyStore))`) — NOT under
 * a path prefix. Mounting at a prefix (e.g. `/auth`) would expose
 * `/auth${path}`, which no verifier looks up and which diverges from the
 * `jwks_uri` OIDC discovery advertises. (This is also why the core
 * `jwksModule` mounts at "/".)
 *
 * `path` defaults to {@link DEFAULT_JWKS_PATH}. Callers that honor the
 * `oauth.jwt.jwksPath` config override resolve it via `resolveJwksPath`
 * and pass the result here, so the registered path always matches the
 * advertised `jwks_uri`.
 */
export const createRouter = (
	express: { Router: () => Router },
	keyStore: KeyStore,
	path: string = DEFAULT_JWKS_PATH,
): Router => {
	const router = express.Router();

	router.get(path, async (_req: Request, res: Response) => {
		if (keyStore.algorithm === "HS256") {
			return res.json({ keys: [] });
		}
		const managedKeys = await keyStore.getVerificationKeys();
		const keys = await Promise.all(
			managedKeys.map(async (mk) => {
				const jwk = await exportJWK(mk.publicKey);
				return { ...jwk, kid: mk.kid, use: "sig", alg: keyStore.algorithm };
			}),
		);
		return res.json({ keys });
	});

	return router;
};
