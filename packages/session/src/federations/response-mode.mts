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
 * How an upstream IdP delivers the authorization response (OAuth 2 Form Post
 * Response Mode / OIDC Core §3.1.2.5 `response_mode`).
 *
 * - `"query"` — the IdP redirects the browser back with the parameters in the
 *   query string. Every federation this package shipped before Sign in with
 *   Apple used this, and it stays the default so nothing has to opt out.
 * - `"form_post"` — the IdP makes the browser POST an
 *   `application/x-www-form-urlencoded` body to the callback. Apple requires
 *   this whenever the requested `scope` includes `name` or `email`, because
 *   the first-authorization `user` field does not fit a redirect URL.
 */
export type FederationResponseMode = "query" | "form_post";

/** The modes the route layer understands, in declaration order. */
export const FEDERATION_RESPONSE_MODES = ["query", "form_post"] as const satisfies readonly [
	FederationResponseMode,
	FederationResponseMode,
];

/**
 * The mode assumed for a provider that declares none — i.e. every federation
 * written against the pre-Apple contract.
 */
export const DEFAULT_FEDERATION_RESPONSE_MODE: FederationResponseMode = "query";

/**
 * Read a provider's declared response mode, falling back to
 * {@link DEFAULT_FEDERATION_RESPONSE_MODE}.
 *
 * An unrecognised value is treated as the default rather than forwarded. A
 * federation adapter is a third-party extension point reached across an
 * untyped boundary (the same reasoning `mergeFederatedClaims` applies to
 * `mapClaims`), so a provider compiled against a different version of this
 * contract must not be able to push an arbitrary token into the upstream
 * authorization request, nor to unlock the POST callback by naming a mode this
 * router has no handler for.
 */
export const resolveFederationResponseMode = (
	provider: Pick<FederationProvider, "responseMode">,
): FederationResponseMode => {
	const declared = provider.responseMode;
	return FEDERATION_RESPONSE_MODES.includes(declared as FederationResponseMode)
		? (declared as FederationResponseMode)
		: DEFAULT_FEDERATION_RESPONSE_MODE;
};

/**
 * Relax the session cookie carrying this federation's ephemeral state to
 * `SameSite=None; Secure`, for the one session that just started a `form_post`
 * federation.
 *
 * A `form_post` callback arrives as a **cross-site POST** from the IdP's
 * origin. A `SameSite=Lax` cookie — the deployment default, and the right
 * default — is not sent on a cross-site POST, so the callback would land with
 * no session, no `state` to compare against and no PKCE verifier: the flow
 * fails closed, but it fails for everyone.
 *
 * The fix is applied **per session, on the start leg of a `form_post`
 * federation only**, never to `session.sameSite` in config. A deployment that
 * runs Apple alongside Google keeps `SameSite=Lax` on every Google login and
 * on every session that never touched a cross-site federation; only the
 * browser that is mid-Apple-flow holds the relaxed cookie. `Secure` is set
 * with it because every current browser drops a `SameSite=None` cookie that is
 * not `Secure` (the same pairing `application.schema.mts` enforces for the
 * config-level value, #282) — and Apple refuses a non-`https` redirect URI
 * anyway, so a `form_post` federation is already HTTPS-only.
 *
 * Takes `unknown` because the session object is supplied by whatever
 * middleware the composition root mounted; returns whether the relaxation
 * actually applied so the caller can say so rather than assume it.
 *
 * Note for express-session: the re-issued `Set-Cookie` reaches the browser
 * because this handler also modifies the session (it writes the federation
 * envelope) and the deployment's `session.maxAge` is required by config
 * schema, which is exactly express-session's condition for re-sending the
 * cookie of an already-established session.
 */
export const applyCrossSiteStateCookie = (session: unknown): boolean => {
	if (session == null || typeof session !== "object") return false;
	const cookie = (session as { cookie?: unknown }).cookie;
	if (cookie == null || typeof cookie !== "object") return false;
	const attributes = cookie as { sameSite?: unknown; secure?: unknown };
	attributes.sameSite = "none";
	attributes.secure = true;
	return true;
};
