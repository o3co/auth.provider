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
 * One rule decides which sections yield a cookie ({@link sessionCookieRefusal}),
 * and the store refuses at boot every section it refuses, so the store mounts
 * no cookie the policy refuses and no section yields a policy that breaks
 * core's contract (`sessionCookiePolicyContract`): a cookie a browser drops (a
 * `__Host-` name that is not secure or that names a domain, a `__Secure-` name
 * or `SameSite=None` without `secure`), a name that is not an RFC 6265 token,
 * and a lifetime outside 1 to `MAX_DURATION_MS` milliseconds. Core's schema
 * already refuses the `SameSite=None` and lifetime cases at validation.
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

/** Why no session cookie is built from a section: the `session.*` key it names, and the rule. */
export interface SessionCookieRefusal {
	readonly key: keyof SessionCookieConfigSlice;
	readonly message: string;
}

/** RFC 6265 §4.1.1: a cookie name is an RFC 2616 token — visible ASCII but separators. */
const COOKIE_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/**
 * Why `session` yields no session cookie, or `undefined` when it yields one.
 * A browser keeps a `__Host-` cookie only when it is secure and names no
 * domain — an empty one included — and a `__Secure-` or `SameSite=None`
 * cookie only when it is secure. A prefix rule names `session.name`, the
 * `SameSite=None` rule `session.secure`, as core's schema does.
 */
export function sessionCookieRefusal(
	session: SessionCookieConfigSlice,
): SessionCookieRefusal | undefined {
	const { name, secure, sameSite, domain, maxAge } = session;
	if (name.startsWith("__Host-") && (secure !== true || domain !== null)) {
		return {
			key: "name",
			message:
				"session.name with __Host- prefix requires session.secure=true and session.domain=null",
		};
	}
	if (!COOKIE_NAME.test(name)) {
		return {
			key: "name",
			message: `session.name ${JSON.stringify(name)} is not a cookie name (an RFC 6265 token)`,
		};
	}
	if (name.startsWith("__Secure-") && secure !== true) {
		return {
			key: "name",
			message: "session.name with __Secure- prefix requires session.secure=true",
		};
	}
	if (sameSite === "none" && secure !== true) {
		return { key: "secure", message: 'session.sameSite = "none" requires session.secure = true' };
	}
	if (!Number.isInteger(maxAge) || maxAge < 1 || maxAge > MAX_DURATION_MS) {
		return {
			key: "maxAge",
			message: `session.maxAge must be a whole number of milliseconds from 1 to ${MAX_DURATION_MS}`,
		};
	}
	return undefined;
}

/**
 * The session cookie's attributes from `session`, frozen. Throws, with the
 * refusal's message, where {@link sessionCookieRefusal} refuses the section.
 */
export function sessionCookiePolicyFrom(session: SessionCookieConfigSlice): SessionCookiePolicy {
	const refusal = sessionCookieRefusal(session);
	if (refusal !== undefined) throw new Error(refusal.message);
	const { name, secure, sameSite, maxAge } = session;
	// As express-session is given it: `null` or empty is a host-only cookie.
	const domain = session.domain || undefined;
	return Object.freeze({ name, secure, sameSite, domain, maxAgeMs: maxAge });
}
