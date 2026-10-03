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
 * The schema of `jwks {}`, the JWKS module's own section. Each key reads the
 * string its environment variable carries; its defaults are applied where it
 * is read (`resolveJwksPath`, `resolveJwksCacheMaxAge`), so the section may be
 * absent or empty. Strict: an unknown key refuses boot, naming its path.
 */

import { z } from "zod";
import { durationFromEnv } from "../config/application.schema.mjs";
import { isValidJwksPath } from "./path.mjs";

export const JWKS_SECTION = z
	.object({
		// Where the key set is published (OIDC `jwks_uri`), under the issuer. An
		// absolute path the router registers as written, so the route and the
		// advertised `jwks_uri` agree.
		path: z
			.string()
			.refine(isValidJwksPath, {
				message:
					"must be an absolute path beginning with '/' with no '//', dot-segments, " +
					"query/fragment, backslash, percent-encoding, or control characters",
			})
			.optional(),
		// `Cache-Control: public, max-age=<N>`, in seconds. Keep it well below
		// the key-overlap window so a rotated kid reaches caching verifiers in
		// time. An empty variable is refused, not served as `max-age=0`.
		cacheMaxAge: durationFromEnv(z.number().int().nonnegative()).optional(),
	})
	.strict()
	.optional();
