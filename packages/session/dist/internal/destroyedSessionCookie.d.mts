/**
 * The session cookie of a session destroyed during the request: the session
 * store module, which sets the cookie, expires it in the same answer,
 * whichever route destroyed the session — `POST /session/logout`, `oauth`'s
 * `/oauth/logout`, or any other. Internal to the package;
 * `modules/sessionStoreModule.mts` is its caller.
 */
import type { SessionCookiePolicy } from "@o3co/auth-provider-core";
import type { RequestHandler } from "express";
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
export declare function expireDestroyedSessionCookie(middleware: RequestHandler, cookie: Pick<SessionCookiePolicy, "name" | "secure" | "sameSite" | "domain">): RequestHandler;
//# sourceMappingURL=destroyedSessionCookie.d.mts.map