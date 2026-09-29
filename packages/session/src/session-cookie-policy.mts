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
 * A policy a browser would drop is refused rather than handed on: the
 * session store refuses a `__Host-` name that is not secure and host-only,
 * and core's schema a cross-site cookie that is not secure; a `__Secure-`
 * name that is not secure and a lifetime that is not one are refused here
 * too, for a configuration that never met the schema.
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

/** The session cookie's attributes from `session`, frozen; throws on a cookie a browser would drop. */
export function sessionCookiePolicyFrom(session: SessionCookieConfigSlice): SessionCookiePolicy {
	const { name, secure, sameSite, maxAge } = session;
	const domain = session.domain || undefined;
	if (name.startsWith("__Host-") && (secure !== true || domain !== undefined)) {
		throw new Error(
			"session.name with __Host- prefix requires session.secure=true and session.domain=null",
		);
	}
	if (name.startsWith("__Secure-") && secure !== true) {
		throw new Error("session.name with __Secure- prefix requires session.secure=true");
	}
	if (sameSite === "none" && secure !== true) {
		throw new Error(
			'session.sameSite = "none" requires session.secure = true: a browser drops a SameSite=None cookie that is not Secure',
		);
	}
	if (!Number.isInteger(maxAge) || maxAge <= 0 || maxAge > MAX_DURATION_MS) {
		throw new Error(
			`session.maxAge must be a whole number of milliseconds from 1 to ${MAX_DURATION_MS}, and was ${JSON.stringify(maxAge)}`,
		);
	}
	return Object.freeze({ name, secure, sameSite, domain, maxAgeMs: maxAge });
}
