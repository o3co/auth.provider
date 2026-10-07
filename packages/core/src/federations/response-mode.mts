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

import type { FederationProvider } from "./types.mjs";

/**
 * How an upstream IdP delivers the authorization response (OAuth 2.0 Form
 * Post Response Mode / OIDC Core §3.1.2.5 `response_mode`).
 *
 * - `"query"` (the default): the browser is redirected back with the
 *   parameters in the query string.
 * - `"form_post"`: the browser POSTs an `application/x-www-form-urlencoded`
 *   body to the callback. Apple requires this when `scope` includes `name` or
 *   `email`, because the first-authorization `user` field does not fit a URL.
 *
 * A `form_post` callback is a cross-site POST, on which a `SameSite=Lax`
 * cookie is not sent. The router gives the flow a cookie of its own rather
 * than changing the session's: the state moves into a federation transaction
 * (an opaque id in a short-lived `__Host-` `SameSite=None; Secure;
 * HttpOnly` cookie of the federation's own, the envelope in a store record; see
 * `federations/transaction.mts` in `@o3co/auth-provider-session`).
 *
 * The session cookie must keep its configured attributes on every session:
 * `GET /session/oauth/federation/:name` needs no authentication, a Lax cookie
 * is sent on a top-level GET, and express-session stores `req.session.cookie`
 * and rebuilds it on every later request. A start leg that wrote to it would
 * let any third party permanently downgrade a victim's session.
 */
export type FederationResponseMode = "query" | "form_post";

/** The modes the route layer understands, in declaration order. */
export const FEDERATION_RESPONSE_MODES = ["query", "form_post"] as const satisfies readonly [
	FederationResponseMode,
	FederationResponseMode,
];

/** The mode assumed for a provider that declares none. */
export const DEFAULT_FEDERATION_RESPONSE_MODE: FederationResponseMode = "query";

/**
 * Read a provider's declared response mode, falling back to
 * {@link DEFAULT_FEDERATION_RESPONSE_MODE}.
 *
 * An unrecognised value falls back rather than being forwarded: an adapter is
 * a third-party extension reached across an untyped boundary, and one built
 * against another version of this contract must not push an arbitrary token
 * into the upstream authorization request, nor unlock the POST callback with
 * a mode this router has no handler for.
 */
export const resolveFederationResponseMode = (
	provider: Pick<FederationProvider, "responseMode">,
): FederationResponseMode => {
	const declared = provider.responseMode;
	return FEDERATION_RESPONSE_MODES.includes(declared as FederationResponseMode)
		? (declared as FederationResponseMode)
		: DEFAULT_FEDERATION_RESPONSE_MODE;
};
