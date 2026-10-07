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
 * The session cookie of a session destroyed during the request: the session
 * store module, which sets the cookie, expires it in the same answer,
 * whichever route destroyed the session — `POST /session/logout`, `oauth`'s
 * `/oauth/logout`, or any other. Internal to the package;
 * `modules/sessionStoreModule.mts` is its caller.
 */

import type { SessionCookiePolicy } from "@o3co/auth-provider-core";
import type { Request, RequestHandler, Response } from "express";
import { sessionCookieAttributes } from "../session-cookie-policy.mjs";

/** A callback operation of express-session's `Session`. */
type SessionOperation = (this: unknown, done?: (err?: unknown) => void) => unknown;

/** The operations that leave a new `Session` object on the request: its successor is watched too. */
const REPLACING_OPERATIONS = ["regenerate", "reload"] as const;

/**
 * express-session's middleware, with the session cookie expired when the
 * request's session is destroyed: once `req.session.destroy` calls back
 * without an error, a `Set-Cookie` for the cookie's name, dated in the past,
 * with the attributes express-session is given ({@link sessionCookieAttributes}),
 * so the browser drops it. express-session itself sets no cookie for a
 * destroyed session, so the answer carries this one line for it.
 *
 * - A destroy the store fails leaves the cookie: the session may still be
 *   there, and the browser's retry needs it.
 * - A regenerated session keeps the new cookie express-session sets for it: a
 *   regenerate drops the old record through the store, never through the
 *   session's `destroy`, so it expires nothing. The session it leaves on the
 *   request is watched in turn, as is the one a reload leaves.
 * - A destroy that completes after the answer was sent changes nothing.
 *
 * The session's methods are replaced on the request's own session object,
 * not enumerable, so the record the store keeps is unchanged. Only the
 * session express-session loads, and those a regenerate or reload leaves, are
 * watched: a session put on the request any other way is not. The cookie is
 * expired at most once per request, however many destroys succeed.
 */
export function expireDestroyedSessionCookie(
	middleware: RequestHandler,
	cookie: Pick<SessionCookiePolicy, "name" | "secure" | "sameSite" | "domain">,
): RequestHandler {
	const attributes = sessionCookieAttributes(cookie);
	return (req, res, next) => {
		middleware(req, res, (err?: unknown) => {
			if (err === undefined || err === null) {
				let expired = false;
				watchSession(req, res, () => {
					if (expired) return;
					expired = true;
					res.clearCookie(cookie.name, attributes);
				});
			}
			next(err);
		});
	};
}

/** Watch the request's session, and each one that replaces it, for a destroy that succeeds. */
function watchSession(req: Request, res: Response, expire: () => void): void {
	const watched = new WeakSet<object>();
	const watch = (): void => {
		const session = (req as unknown as { session?: unknown }).session;
		if (typeof session !== "object" || session === null || watched.has(session)) return;
		watched.add(session);
		const own = session as Record<string, SessionOperation>;
		const destroy = own.destroy;
		if (typeof destroy === "function") {
			replace(session, "destroy", function (this: unknown, done) {
				return destroy.call(this, (err) => {
					if (!err && !res.headersSent) expire();
					done?.(err);
				});
			});
		}
		for (const name of REPLACING_OPERATIONS) {
			const operation = own[name];
			if (typeof operation !== "function") continue;
			replace(session, name, function (this: unknown, done) {
				return operation.call(this, (err) => {
					watch();
					done?.(err);
				});
			});
		}
	};
	watch();
}

/** Put `operation` on `session` itself, not enumerable, where its prototype's method was. */
function replace(session: object, name: string, operation: SessionOperation): void {
	Object.defineProperty(session, name, {
		value: operation,
		configurable: true,
		enumerable: false,
		writable: true,
	});
}
