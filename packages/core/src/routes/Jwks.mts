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
import type { KeyStore } from "../keys/KeyStore.mjs";

export const createRouter = (express: { Router: () => Router }, keyStore: KeyStore): Router => {
	const router = express.Router();

	router.get("/.well-known/jwks.json", async (_req: Request, res: Response) => {
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
