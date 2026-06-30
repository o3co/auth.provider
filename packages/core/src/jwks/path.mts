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
 * Default path at which the JSON Web Key Set is published. Unlike
 * `/.well-known/openid-configuration` (fixed by RFC 8414), `jwks_uri` is
 * operator-choosable per OIDC Discovery — this is the near-universal
 * convention and the default when `oauth.jwt.jwksPath` is unset.
 */
export const DEFAULT_JWKS_PATH = "/.well-known/jwks.json";

/**
 * Resolve the JWKS publishing path for a deployment. This is the SINGLE
 * source of truth for both (a) where the JWKS route registers itself and
 * (b) the `jwks_uri` OIDC discovery advertises. The core `jwksModule` and
 * the oauth discovery route MUST both resolve the path through this
 * function so the two endpoints can never drift — neither the config key
 * (`oauth.jwt.jwksPath`) nor the default is duplicated at a call site.
 *
 * The configured value is validated as an absolute path by the config
 * schema (`oauth.jwt.jwksPath`); this resolver only applies the default.
 */
export const resolveJwksPath = (config: { oauth?: { jwt?: { jwksPath?: unknown } } }): string => {
	const configured = config.oauth?.jwt?.jwksPath;
	// Intentionally lenient: the config schema is the authoritative guard (it
	// rejects non-absolute / non-string `jwksPath` at parse time), so at runtime
	// `configured` is either a valid absolute string or absent. The typeof/length
	// check is defensive belt-and-suspenders for callers that bypass the schema
	// (e.g. hand-built config objects) — fall back to the default rather than
	// publishing keys at a malformed path.
	return typeof configured === "string" && configured.length > 0 ? configured : DEFAULT_JWKS_PATH;
};
