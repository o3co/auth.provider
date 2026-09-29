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
 * The login page's URL rule (#728, #750): what every sender of a browser to
 * the login page does to the page — the one home of the rule `LoginEntry`
 * states, so `/authorize`'s own fallback (oauth, when no module provides the
 * slot) and the session package's `loginEntry` cannot drift apart.
 *
 * The page's own query is the text before any `#`, after the first `?` — as
 * the redirect writes it, so a fragment is never mistaken for the query and a
 * URL that `URL` cannot parse is read all the same. `redirect_to` joins that
 * query (`&` when the page has one, `?` otherwise) before the fragment, which
 * is kept; the target is encoded whole with `encodeURIComponent`, never as a
 * form, so nothing of it reads as the page's query or fragment.
 */

/** The parameter a login page reads where to come back to from. */
export const LOGIN_RETURN_PARAMETER = "redirect_to";

/** `url` split at its first `#`: the page before it, and the fragment with its `#`. */
const splitFragment = (url: string): readonly [string, string] => {
	const at = url.indexOf("#");
	return at === -1 ? [url, ""] : [url.slice(0, at), url.slice(at)];
};

/**
 * Whether `page`'s own query already carries `redirect_to` — the name matched
 * as `URLSearchParams.has` matches it, so `redirect%5Fto` and one with no
 * value count. Such a page is refused: a sender adds `redirect_to`, and the
 * page would receive two.
 */
export function loginPageCarriesReturn(page: string): boolean {
	const [beforeFragment] = splitFragment(page);
	const queryAt = beforeFragment.indexOf("?");
	return (
		queryAt !== -1 &&
		new URLSearchParams(beforeFragment.slice(queryAt + 1)).has(LOGIN_RETURN_PARAMETER)
	);
}

/** `page` with `redirect_to` naming `returnTo` added to its query, before any fragment. */
export function loginPageUrlFor(page: string, returnTo: string): string {
	const [beforeFragment, fragment] = splitFragment(page);
	const joiner = beforeFragment.includes("?") ? "&" : "?";
	return `${beforeFragment}${joiner}${LOGIN_RETURN_PARAMETER}=${encodeURIComponent(returnTo)}${fragment}`;
}
