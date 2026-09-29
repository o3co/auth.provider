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
 * `sessionCookiePolicy` slot the session store's module provides, for a module
 * that sets a cookie of its own beside the session's or sizes what must
 * outlive a session, instead of reading `session.*`.
 *
 * The attributes are the ones express-session is given
 * (`./modules/sessionStoreModule.mts`): `session.name`, `session.secure`,
 * `session.sameSite`, `session.domain` (`null` or empty: a host-only cookie)
 * and `session.maxAge`, the cookie's `Max-Age` and a session record's
 * lifetime. The signing secret is not among them.
 *
 * It refuses what would break core's contract (`sessionCookiePolicyContract`),
 * so no section yields a policy a reader cannot trust: first what the store
 * refuses, with the store's message ({@link assertHostPrefixKept}), then a
 * cookie a browser drops (a name that is not an RFC 6265 token, a `__Secure-`
 * name or `SameSite=None` without `secure`) and a lifetime outside 1 to
 * `MAX_DURATION_MS` milliseconds. Core's schema already refuses the
 * `SameSite=None` and lifetime cases at validation.
 */

import { MAX_DURATION_MS, type SessionCookiePolicy } from "@o3co/auth-provider-core";

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

/** RFC 6265 §4.1.1: a cookie name is an RFC 2616 token — visible ASCII but separators. */
const COOKIE_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/**
 * The session cookie's attributes from `session`, frozen. Throws where the
 * session store does ({@link assertHostPrefixKept}), and where the policy
 * would break core's contract.
 */
export function sessionCookiePolicyFrom(session: SessionCookieConfigSlice): SessionCookiePolicy {
	assertHostPrefixKept(session);
	const { name, secure, sameSite, maxAge } = session;
	if (!COOKIE_NAME.test(name)) {
		throw new Error(
			`session.name ${JSON.stringify(name)} is not a cookie name (an RFC 6265 token)`,
		);
	}
	if (name.startsWith("__Secure-") && secure !== true) {
		throw new Error("session.name with __Secure- prefix requires session.secure=true");
	}
	if (sameSite === "none" && secure !== true) {
		throw new Error('session.sameSite = "none" requires session.secure = true');
	}
	if (!Number.isInteger(maxAge) || maxAge < 1 || maxAge > MAX_DURATION_MS) {
		throw new Error(
			`session.maxAge must be a whole number of milliseconds from 1 to ${MAX_DURATION_MS}`,
		);
	}
	// As express-session is given it: `null` or empty is a host-only cookie.
	const domain = session.domain || undefined;
	return Object.freeze({ name, secure, sameSite, domain, maxAgeMs: maxAge });
}
