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
 * outlive a session, instead of reading `session-store.*`.
 *
 * The attributes are the ones express-session is given
 * (`./modules/sessionStoreModule.mts`): `session-store.name`,
 * `session-store.secure`, `session-store.sameSite`, `session-store.domain`
 * (`null` or empty: a host-only cookie) and `session-store.maxAge`, the
 * cookie's `Max-Age` and a session record's lifetime. The signing secret is
 * not among them.
 *
 * One rule ({@link sessionCookieRefusal}) decides which sections yield a
 * cookie; the store's section schema refuses at validation what it refuses,
 * so no section yields a policy that breaks core's contract
 * (`sessionCookiePolicyContract`) or a cookie the store mounts and the policy
 * refuses.
 */

import { MAX_DURATION_MS, type SessionCookiePolicy } from "@o3co/auth-provider-core";

/** The `session-store.*` keys the policy is read from. */
export interface SessionCookieConfigSlice {
	readonly name: string;
	readonly secure: boolean;
	readonly sameSite: "lax" | "strict" | "none";
	readonly domain: string | null;
	readonly maxAge: number;
}

/** Why no session cookie is built from a section: the `session-store.*` key it names, and the rule. */
export interface SessionCookieRefusal {
	readonly key: "name" | "secure" | "domain" | "maxAge";
	readonly message: string;
}

/** RFC 6265 §4.1.1: a cookie name is an RFC 2616 token — visible ASCII but separators. */
const COOKIE_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/** A `Domain` a cookie can carry: LDH labels, one leading dot allowed (the `cookie` package's rule). */
const COOKIE_DOMAIN =
	/^([.]?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)([.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;

/** RFC 6265bis: browsers match the `__Host-` and `__Secure-` prefixes case-insensitively. */
const HOST_PREFIX = /^__host-/i;
const SECURE_PREFIX = /^__secure-/i;

/**
 * Why `session-store` yields no session cookie, or `undefined`: a cookie a browser
 * drops (a `__Host-` name not secure or with a domain, an empty one included; a
 * `__Secure-` name or `SameSite=None` not secure), a name that is not an RFC
 * 6265 token, a domain a cookie cannot carry, a lifetime outside 1 to
 * `MAX_DURATION_MS` ms.
 */
export function sessionCookieRefusal(
	session: SessionCookieConfigSlice,
): SessionCookieRefusal | undefined {
	const { name, secure, sameSite, domain, maxAge } = session;
	if (HOST_PREFIX.test(name) && (secure !== true || domain !== null)) {
		return {
			key: "name",
			message:
				"session-store.name with __Host- prefix requires session-store.secure=true and session-store.domain=null",
		};
	}
	if (!COOKIE_NAME.test(name)) {
		return {
			key: "name",
			message: `session-store.name ${JSON.stringify(name)} is not a cookie name (an RFC 6265 token)`,
		};
	}
	if (SECURE_PREFIX.test(name) && secure !== true) {
		return {
			key: "name",
			message: "session-store.name with __Secure- prefix requires session-store.secure=true",
		};
	}
	if (domain !== null && domain !== "" && !COOKIE_DOMAIN.test(domain)) {
		return {
			key: "domain",
			message: `session-store.domain ${JSON.stringify(domain)} is not a cookie domain (a host name, one leading dot allowed)`,
		};
	}
	if (sameSite === "none" && secure !== true) {
		return {
			key: "secure",
			message:
				'session-store.sameSite = "none" requires session-store.secure = true (SESSION_STORE_SECURE=true): browsers drop a SameSite=None cookie that is not Secure',
		};
	}
	if (!Number.isInteger(maxAge) || maxAge < 1 || maxAge > MAX_DURATION_MS) {
		return {
			key: "maxAge",
			message: `session-store.maxAge must be a whole number of milliseconds from 1 to ${MAX_DURATION_MS}`,
		};
	}
	return undefined;
}

/**
 * The session cookie's attributes from `session-store`, frozen. Throws, with the
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
