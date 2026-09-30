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
import { coreReference } from "../config/references.mjs";
import { defineModule } from "../modules/index.mjs";
import { resolveJwksCacheMaxAge } from "./cache.mjs";
import { resolveJwksPath } from "./path.mjs";
import { createRouter as createJwksRouter } from "./router.mjs";
import { JWKS_SECTION } from "./section.mjs";

/**
 * JWKS publishing module: contributes the `/.well-known/jwks.json` route (or
 * `jwks.path`) so verifiers (BFFs, RPs) can validate tokens offline.
 *
 * Built from its own section, `jwks { path, cacheMaxAge }`, alone; core's own
 * `reference.conf` binds each key's variable (`JWKS_PATH`,
 * `JWKS_CACHE_MAX_AGE`). The keys' old paths, `oauth.jwt.jwksPath` and
 * `oauth.jwt.jwksCacheMaxAge`, refuse boot naming the new ones.
 *
 * Unlike OIDC discovery (issuer-gated, in the oauth module), it depends only
 * on the `keyStore` and is mounted whenever the provider signs tokens. For
 * HS256 the route answers `404 jwks_not_published` with `Cache-Control:
 * no-store`: the secret is never published, and an empty set would be cached
 * by verifiers as "a provider with no keys".
 *
 * The route registers an absolute path, so the contribution mounts at "/".
 *
 * `express` is resolved lazily via `createRequire`: it is an optional peer
 * dependency of core, and a static import would stop core loading for
 * non-HTTP consumers that omit this module. Same pattern as
 * `boot/assemble-app.mts`.
 */
export const jwksModule = defineModule({
	name: "jwks",
	section: {
		schema: JWKS_SECTION,
		reference: coreReference(),
		relocatedFrom: {
			"oauth.jwt.jwksPath": "path",
			"oauth.jwt.jwksCacheMaxAge": "cacheMaxAge",
		},
	},
	requires: ["keyStore"] as const,
	optional: ["logger"] as const,
	contributes: {
		routes: [
			async (deps) => {
				const require = createRequire(import.meta.url);
				const express = require("express") as { Router: () => Router };
				const jwks = { jwks: deps.section ?? {} };
				// One path for both the router and the route advertisement, so the
				// boot collision checker catches a second module claiming GET
				// <path>, which would otherwise shadow the route `jwks_uri` names.
				const path = resolveJwksPath(jwks);
				return {
					id: "jwks",
					mountPath: "/",
					handler: createJwksRouter(express, deps.keyStore, {
						path,
						cacheMaxAgeSeconds: resolveJwksCacheMaxAge(jwks),
						...(deps.logger ? { logger: deps.logger } : {}),
					}),
					routes: [{ method: "GET", path }],
				};
			},
		],
		// `jwks_uri` is owned here and resolved through the same `resolveJwksPath`
		// as the route, so the two cannot drift. The aggregator prefixes it with
		// the issuer and emits the document only when an issuer is configured.
		discoveryMetadata: [
			(deps) => ({ endpoints: { jwks_uri: resolveJwksPath({ jwks: deps.section ?? {} }) } }),
		],
	},
});
