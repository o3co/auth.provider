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
 * The test double of the `loginEntry` slot. `createTestLoginEntry` keeps the
 * protocol `/authorize` and the federation-grants connect flow send a
 * browser by — `redirect_to` added once to the page's own query, before any
 * fragment, the target encoded whole — for `/login` by default. The contract
 * suite is `@o3co/auth-provider-test-kit`'s. Published on
 * `@o3co/auth-provider-core/testing`.
 */

import { loginPageCarriesReturn, loginPageUrlFor } from "../../browser-session/login-page.mjs";
import type { LoginEntry } from "../../browser-session/types.mjs";

/** The parameter a login page reads where to come back to from. */
const RETURN_PARAMETER = "redirect_to";

/**
 * A `LoginEntry` for `url` — the fixture configuration's `/login` by
 * default — over core's login-page rule (`loginPageUrlFor`,
 * `loginPageCarriesReturn`): `redirect_to` joined with `?`, or `&` to a page
 * that has a query, before any fragment, the target encoded whole; a page
 * whose own query carries `redirect_to` is refused. Frozen.
 */
export function createTestLoginEntry(url = "/login"): LoginEntry {
	if (loginPageCarriesReturn(url)) {
		throw new TypeError(
			`createTestLoginEntry: the login page must not carry "${RETURN_PARAMETER}" of its own, and was ${JSON.stringify(url)}`,
		);
	}
	return Object.freeze({
		url,
		urlFor: (returnTo: string): string => loginPageUrlFor(url, returnTo),
	});
}
