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
 * Transport validation for the Store endpoints `HttpUserRepository` posts to:
 * `https://`, or `http://` to a loopback host only (`localhost`,
 * `127.0.0.0/8`, `[::1]`), because these endpoints receive plaintext user
 * credentials. See README, Constructor validation.
 *
 * Kept separate from `oauth.jwt.issuer`'s rule (core's `checkCanonicalIssuer`)
 * because an issuer may not carry a query string, while a Store endpoint may.
 * The loopback predicate is core's `isLoopbackHostname`, the session redirect
 * policy's too, so the carve-outs cannot drift apart. A message names an
 * endpoint by origin and path alone ({@link endpointForMessage}): a query may
 * carry a credential, and every caller logs what the repository throws.
 */

import { isLoopbackHostname } from "@o3co/auth-provider-core";

// Re-exported unchanged: this module's callers (and its tests) read the
// predicate as part of the endpoint-validation surface. The definition lives
// in core.
export { isLoopbackHostname };

/** Why a candidate endpoint was rejected, phrased for a boot-time error. */
export type EndpointRejection =
	| "not-a-string"
	| "empty"
	| "not-absolute-url"
	| "unsupported-scheme"
	| "insecure-scheme"
	| "has-credentials";

/** Matches `scheme://` — the shape that distinguishes an absolute URL from a bare host. */
const ABSOLUTE_URL_PREFIX = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//;

/**
 * Returns `null` when `value` is a usable Store endpoint, otherwise the reason
 * it is not. See the module comment for the loopback carve-out.
 */
export function checkSecureEndpoint(value: unknown): EndpointRejection | null {
	if (typeof value !== "string") return "not-a-string";
	if (value === "") return "empty";

	// `new URL("users.example.com:3000")` succeeds with `users.example.com:` as
	// the scheme and no host, so a bare host is reported as the missing-scheme
	// mistake it is rather than as an exotic scheme.
	if (!ABSOLUTE_URL_PREFIX.test(value)) return "not-absolute-url";

	let url: URL;
	try {
		url = new URL(value);
	} catch {
		return "not-absolute-url";
	}

	if (url.protocol !== "https:" && url.protocol !== "http:") return "unsupported-scheme";
	// No empty-host check is needed below: `http` and `https` are "special"
	// schemes, for which the WHATWG parser requires a non-empty host — a
	// host-less `https://` or `https://:8080/x` throws above and is reported as
	// `not-absolute-url` rather than reaching here with `hostname === ""`.
	if (url.protocol === "http:" && !isLoopbackHostname(url.hostname)) return "insecure-scheme";
	if (url.username !== "" || url.password !== "") return "has-credentials";

	return null;
}

/**
 * Operator-facing explanation for each rejection reason.
 *
 * This is what an operator reads at boot when their Store URL is refused, so
 * every message states the **actual** rule rather than a simplification of it.
 * In particular both scheme messages name the loopback carve-out: saying only
 * "must use https" would contradict a policy that does accept `http://` on
 * loopback, and send someone hunting for a certificate they do not need.
 */
export function describeEndpointRejection(reason: EndpointRejection): string {
	switch (reason) {
		case "not-a-string":
			return "must be a string";
		case "empty":
			return 'must not be empty (an unset or blank environment variable substitutes as "")';
		case "not-absolute-url":
			return (
				"must be an absolute URL with a host (e.g. https://users.example.com/authenticate), " +
				"not a bare host or a path"
			);
		case "unsupported-scheme":
			return (
				"must use https, or http for a loopback host (localhost, 127.0.0.0/8, [::1]) — " +
				"no other scheme is accepted"
			);
		case "insecure-scheme":
			return (
				"must use https — it carries plaintext user credentials; http is accepted only for " +
				"a loopback host (localhost, 127.0.0.0/8, [::1])"
			);
		case "has-credentials":
			return "must not embed credentials in the URL";
	}
}

/**
 * Returns `value` when it is a usable Store endpoint, otherwise throws naming
 * `field` and the reason.
 *
 * The rejected value is deliberately **not** echoed into the message: it is
 * operator-supplied configuration that may embed a secret, and a boot error
 * lands in logs.
 */
export function assertSecureEndpoint(value: unknown, field: string): string {
	const rejection = checkSecureEndpoint(value);
	if (rejection !== null) {
		throw new Error(
			`HttpUserRepository: "${field}" ${describeEndpointRejection(rejection)} ` +
				`(reason: ${rejection})`,
		);
	}
	return value as string;
}

/**
 * `url` as a message names it: its origin and path, as the WHATWG URL parser
 * normalises them (`https://store.example/authenticate`), and never its query
 * or fragment, which may carry a credential. Anything that is not an http or
 * https URL is named by what it is not, since its origin would be `"null"` and
 * its path the rest of it (`data:…`): the constructor refuses such a Store URL,
 * but a caller can hand `StoreCredentialRefusedError` anything.
 */
export function endpointForMessage(url: string): string {
	try {
		const { protocol, origin, pathname } = new URL(url);
		if (protocol === "http:" || protocol === "https:") return `${origin}${pathname}`;
	} catch {
		// Named below, like any other value that is not an http or https URL.
	}
	return "(an endpoint that is not an http or https URL)";
}
