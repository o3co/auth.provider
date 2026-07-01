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

import { createRequire } from "node:module";
import type { Router } from "express";
import { defineModule } from "../modules/index.mjs";
import { createRouter as createJwksRouter } from "../routes/Jwks.mjs";
import { resolveJwksCacheMaxAge } from "./cache.mjs";
import { resolveJwksPath } from "./path.mjs";

/**
 * JWKS publishing module. Contributes the `/.well-known/jwks.json` route
 * (or the `oauth.jwt.jwksPath` override) so every provider that signs
 * tokens exposes its verification keys for offline validation by verifiers
 * (BFFs, RPs).
 *
 * Unlike OIDC discovery (issuer-gated, contributed by the oauth module),
 * JWKS publishing is a key-management concern: it depends ONLY on the
 * `keyStore` and is mounted whenever the provider signs tokens, independent
 * of whether an OIDC issuer is configured. For HS256 (symmetric) the route
 * returns an empty key set — the secret is never published.
 *
 * The route registers an absolute path, so the contribution mounts at "/"
 * to avoid path doubling.
 *
 * `express` is resolved lazily inside the (async) route factory via
 * `createRequire` rather than a static import. core declares `express` as
 * an OPTIONAL peer dependency; a static import would make
 * `@o3co/auth-provider-core` fail to load for non-HTTP consumers that omit
 * this module from their manifest. Mirrors the peer-resolution pattern in
 * `boot/assemble-app.mts`.
 */
export const jwksModule = defineModule({
	name: "jwks",
	requires: ["config", "keyStore"] as const,
	contributes: {
		routes: [
			async (deps) => {
				const require = createRequire(import.meta.url);
				const express = require("express") as { Router: () => Router };
				const config = deps.config as {
					oauth?: { jwt?: { jwksPath?: unknown; jwksCacheMaxAge?: unknown } };
				};
				// Resolve the path once and use it for BOTH the router registration
				// and the route advertisement, so the boot collision checker can
				// detect a second module claiming the same effective GET <jwksPath>
				// (the router mounts at "/", so effective path === jwksPath). Without
				// the advertisement the JWKS route could be silently shadowed and the
				// advertised `jwks_uri` would resolve to the wrong handler.
				const path = resolveJwksPath(config);
				return {
					id: "jwks",
					mountPath: "/",
					handler: createJwksRouter(express, deps.keyStore, {
						path,
						cacheMaxAgeSeconds: resolveJwksCacheMaxAge(config),
					}),
					routes: [{ method: "GET", path }],
				};
			},
		],
		// OIDC discovery `jwks_uri` is a key-management concern owned by this
		// module, so jwks contributes it rather than the oauth module guessing
		// the path. Resolved through the same `resolveJwksPath` the route above
		// uses, so the advertised URI and the registered route can never drift.
		// The aggregator prefixes this issuer-relative path with the issuer and
		// only emits the document when an issuer is configured.
		discoveryMetadata: [
			(deps) => {
				const config = deps.config as { oauth?: { jwt?: { jwksPath?: unknown } } };
				return { endpoints: { jwks_uri: resolveJwksPath(config) } };
			},
		],
	},
});
