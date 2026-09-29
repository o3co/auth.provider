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
 * The session cookie's attributes as core's `SessionCookiePolicy` — the
 * `sessionCookiePolicy` slot the session store's module provides (#728),
 * for a module that sets a cookie of its own beside the session's or sizes
 * what must outlive a session, instead of reading `session.*`.
 *
 * The attributes are the ones express-session is given
 * (`./modules/sessionStoreModule.mts`): `session.name`, `session.secure`,
 * `session.sameSite`, `session.domain` — `null`, or empty, a host-only
 * cookie — and `session.maxAge`, the cookie's `Max-Age` and a session
 * record's lifetime. The signing secret is not among them.
 *
 * It refuses exactly what the session store refuses of the cookie
 * ({@link assertHostPrefixKept}, which the store runs too): a `__Host-` name
 * that is not secure, or that names a domain — the store compares it with
 * `null`, so an empty one is refused as well. Core's contract holds a policy
 * to more — a `__Secure-` name and a `SameSite=None` cookie only secure, a
 * lifetime within the one-year ceiling — which the store does not refuse
 * (core's schema refuses the second and the third at validation); those
 * become this policy's refusals with the store's own, not before.
 */

import type { SessionCookiePolicy } from "@o3co/auth-provider-core";

/** The `session.*` keys the policy is read from. */
export interface SessionCookieConfigSlice {
	readonly name: string;
	readonly secure: boolean;
	readonly sameSite: "lax" | "strict" | "none";
	readonly domain: string | null;
	readonly maxAge: number;
}

/**
 * The session store's one rule of the cookie: a `__Host-` name is kept by a
 * browser only when the cookie is secure and names no domain, so such a name
 * with `secure` off or any `domain` — an empty one included — is refused.
 */
export function assertHostPrefixKept(
	session: Pick<SessionCookieConfigSlice, "name" | "secure" | "domain">,
): void {
	if (session.name.startsWith("__Host-") && (session.secure !== true || session.domain !== null)) {
		throw new Error(
			"session.name with __Host- prefix requires session.secure=true and session.domain=null",
		);
	}
}

/** The session cookie's attributes from `session`, frozen; throws where the session store does ({@link assertHostPrefixKept}). */
export function sessionCookiePolicyFrom(session: SessionCookieConfigSlice): SessionCookiePolicy {
	assertHostPrefixKept(session);
	const { name, secure, sameSite, maxAge } = session;
	// As express-session is given it: `null` or empty is a host-only cookie.
	const domain = session.domain || undefined;
	return Object.freeze({ name, secure, sameSite, domain, maxAgeMs: maxAge });
}
