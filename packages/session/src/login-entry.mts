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
 * The deployment's login page as core's `LoginEntry` — the `loginEntry` slot
 * the session module provides (#728): the page a browser that is not signed
 * in is sent to (`endpoints.login.url`), and the `redirect_to` protocol that
 * brings it back. `/authorize` and the federation-grants connect flow built
 * that URL by hand from the configuration; they read it here instead.
 *
 * The protocol is theirs as it was: `redirect_to` added to the page's own
 * query — `&`-joined when the page already has one, since a second `?` would
 * corrupt both parameters — the target encoded whole, so nothing of it reads
 * as the page's query or fragment. What comes back is the login route's to
 * hold to its allowlist.
 */

import type { LoginEntry } from "@o3co/auth-provider-core";

/** The parameter a login page reads where to come back to from. */
const RETURN_PARAMETER = "redirect_to";

/**
 * Whether `page` carries the return parameter in its own query, read as
 * `urlFor` writes it: the text before any `#`, after the first `?`, the name
 * matched as `URLSearchParams.has` matches it (so `redirect%5Fto` and one
 * with no value count). The same rule oauth's configSchema holds
 * `endpoints.login.url` to.
 */
const carriesReturnParameter = (page: string): boolean => {
	const beforeFragment = page.split("#", 1)[0] ?? "";
	const queryAt = beforeFragment.indexOf("?");
	return (
		queryAt !== -1 && new URLSearchParams(beforeFragment.slice(queryAt + 1)).has(RETURN_PARAMETER)
	);
};

/**
 * The login entry for the page `url` — a path or an absolute URL, which may
 * carry a query and a fragment of its own, but not `redirect_to`: `urlFor`
 * adds it, and a page that carried one would send two. `urlFor` adds
 * `redirect_to` to the page's query, before any fragment, the target encoded
 * whole. Frozen.
 */
export function createLoginEntry(url: string): LoginEntry {
	if (typeof url !== "string" || url === "") {
		throw new TypeError(
			`createLoginEntry: the login page must be a non-empty string, and was ${JSON.stringify(url)}`,
		);
	}
	if (carriesReturnParameter(url)) {
		throw new TypeError(
			`createLoginEntry: the login page must not carry a "${RETURN_PARAMETER}" query parameter of its own — urlFor adds it — and was ${JSON.stringify(url)}`,
		);
	}
	const fragmentAt = url.indexOf("#");
	const page = fragmentAt === -1 ? url : url.slice(0, fragmentAt);
	const fragment = fragmentAt === -1 ? "" : url.slice(fragmentAt);
	const joiner = page.includes("?") ? "&" : "?";
	return Object.freeze({
		url,
		urlFor: (returnTo: string): string =>
			`${page}${joiner}${RETURN_PARAMETER}=${encodeURIComponent(returnTo)}${fragment}`,
	});
}

/**
 * The login entry for `endpoints.login.url`.
 *
 * Built whether or not the page is configured. Core's schema takes any
 * string, the empty one included, and a hand-built configuration may leave
 * the key out; the oauth module's schema requires a page, and the
 * federation-grants connect flow refuses to boot enabled without one. So a
 * composition that installs a consumer of the slot and never sends a browser
 * to log in boots as it did. Without a page, the entry fails where the page
 * is read, naming the key: `url` and `urlFor` throw.
 */
export function loginEntryFromConfig(config: unknown): LoginEntry {
	const written = (config as { endpoints?: { login?: { url?: unknown } } } | undefined)?.endpoints
		?.login?.url;
	if (typeof written === "string" && written !== "") return createLoginEntry(written);
	const unconfigured = (): never => {
		throw new Error(
			"endpoints.login.url is not configured: a browser that is not signed in has no login page to be sent to",
		);
	};
	return Object.freeze(
		Object.defineProperties({} as LoginEntry, {
			url: { get: unconfigured, enumerable: true },
			urlFor: { value: unconfigured, enumerable: true },
		}),
	);
}
