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
 * Whether `path` is a valid JWKS publishing path: the single rule shared by
 * the config schema, {@link resolveJwksPath} and `createJwksRouter`, so the
 * registered route and the advertised `jwks_uri` agree. Rejects anything
 * Express or a URL parser could normalize to a different path: `?`, `#`, `\`,
 * `%` (e.g. `%2e%2e`), control and whitespace characters, and empty, `.` or
 * `..` segments (`//`, a trailing `/`).
 */
export function isValidJwksPath(path: unknown): path is string {
	if (typeof path !== "string" || !path.startsWith("/")) return false;
	for (const ch of path) {
		const code = ch.codePointAt(0) ?? 0;
		if (code <= 0x20 || code === 0x7f) return false; // control chars + space
		if (ch === "?" || ch === "#" || ch === "\\" || ch === "%") return false;
	}
	const segments = path.split("/");
	// `segments[0]` is the empty string before the leading "/". Any OTHER empty
	// segment is an internal "//" or a trailing "/", and any "."/".." is a
	// dot-segment — all of which normalize to a different dereferenced path than
	// the route registers. (This also covers a leading "//".)
	return !segments.slice(1).includes("") && !segments.includes(".") && !segments.includes("..");
}

/**
 * Resolves the JWKS publishing path: the single source for where the route
 * registers and the `jwks_uri` discovery advertises. `jwksModule` and the
 * oauth discovery route MUST both call it, so neither the config key nor the
 * default is duplicated. Re-applies {@link isValidJwksPath} so a caller that
 * bypasses the schema falls back to the default, not a malformed path.
 */
export const resolveJwksPath = (config: { oauth?: { jwt?: { jwksPath?: unknown } } }): string => {
	const configured = config.oauth?.jwt?.jwksPath;
	return isValidJwksPath(configured) ? configured : DEFAULT_JWKS_PATH;
};
