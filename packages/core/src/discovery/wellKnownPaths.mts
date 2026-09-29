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

/** OpenID Connect Discovery 1.0 §4: the suffix appended to the issuer. */
export const OIDC_DISCOVERY_PATH = "/.well-known/openid-configuration";

/** RFC 8414 §3: the well-known string inserted between host and path. */
export const OAUTH_METADATA_PATH = "/.well-known/oauth-authorization-server";

export interface DiscoveryPaths {
	/** Where OIDC Discovery clients look. */
	readonly oidc: readonly string[];
	/** Where RFC 8414 clients look. */
	readonly oauth: readonly string[];
}

/**
 * The paths one authorization-server metadata document is served at, for an
 * issuer identifier. The discovery route, its route advertisement and the
 * CORS allowlist all read this, so the three cannot drift.
 *
 * For an issuer with a path (`https://as.example/tenant-a`), OIDC Discovery
 * 1.0 §4 appends (`/tenant-a/.well-known/openid-configuration`) and RFC 8414 §3
 * inserts (`/.well-known/oauth-authorization-server/tenant-a`). Clients differ
 * in which they probe, so both are served with the same document.
 *
 * The root OIDC path is kept for a path-bearing issuer too: routes are mounted
 * at the router's root, so such an issuer works only behind a proxy that
 * strips the issuer path or with the router mounted at that path, and in both
 * the client's appended URL reaches this router as the root form. A router
 * mounted at the issuer path never receives the inserted RFC 8414 form unless
 * that path is also routed to it. The RFC 8414 root form is not served: it
 * would answer for `https://as.example`, which an RFC 8414 §3.3 client must
 * reject.
 *
 * An issuer that is not a URL, or has no path, gets the two root forms.
 */
export function discoveryPathsFor(issuer: string | undefined): DiscoveryPaths {
	const path = issuerPath(issuer);
	if (path === "") {
		return { oidc: [OIDC_DISCOVERY_PATH], oauth: [OAUTH_METADATA_PATH] };
	}
	return {
		oidc: [OIDC_DISCOVERY_PATH, `${path}${OIDC_DISCOVERY_PATH}`],
		oauth: [`${OAUTH_METADATA_PATH}${path}`],
	};
}

/** The issuer's path component without a trailing slash, or `""` when it has none. */
function issuerPath(issuer: string | undefined): string {
	if (issuer === undefined || issuer.length === 0) return "";
	let pathname: string;
	try {
		pathname = new URL(issuer).pathname;
	} catch {
		return "";
	}
	const trimmed = pathname.replace(/\/+$/, "");
	return trimmed === "" || trimmed === "/" ? "" : trimmed;
}
