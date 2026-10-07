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
 * {@link sessionCookieAttributes} is the one statement of the attributes the
 * cookie is set with — the ones express-session is given, and the ones the
 * cookie of a destroyed session is expired with, so a browser matches the two.
 *
 * One rule ({@link sessionCookieRefusal}) decides which sections yield a
 * cookie; the store's section schema refuses at validation what it refuses,
 * so no section yields a policy that breaks core's contract
 * (`sessionCookiePolicyContract`) or a cookie the store mounts and the policy
 * refuses.
 */
import { type SessionCookiePolicy } from "@o3co/auth-provider-core";
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
/**
 * Why `session-store` yields no session cookie, or `undefined`: a cookie a browser
 * drops (a `__Host-` name not secure or with a domain, an empty one included; a
 * `__Secure-` name or `SameSite=None` not secure), a name that is not an RFC
 * 6265 token, a domain a cookie cannot carry, a lifetime outside 1 to
 * `MAX_DURATION_MS` ms.
 */
export declare function sessionCookieRefusal(session: SessionCookieConfigSlice): SessionCookieRefusal | undefined;
/**
 * The session cookie's attributes from `session-store`, frozen. Throws, with the
 * refusal's message, where {@link sessionCookieRefusal} refuses the section.
 */
export declare function sessionCookiePolicyFrom(session: SessionCookieConfigSlice): SessionCookiePolicy;
/** The attributes the session cookie is set with, beside its name and lifetime. */
export interface SessionCookieAttributes {
    readonly path: "/";
    readonly httpOnly: true;
    readonly secure: boolean;
    readonly sameSite: "lax" | "strict" | "none";
    readonly domain: string | undefined;
}
/**
 * The attributes the session cookie is set with, from its policy: on every
 * path, never readable by script, and the policy's `Secure`, `SameSite` and
 * `Domain`. What express-session is given, and what the cookie of a
 * destroyed session is expired with: a browser drops a cookie only when the
 * attributes match.
 * `Path=/` and `HttpOnly` are this package's, not the policy's: they hold
 * because this package's session store module sets the cookie.
 */
export declare function sessionCookieAttributes(policy: Pick<SessionCookiePolicy, "secure" | "sameSite" | "domain">): SessionCookieAttributes;
//# sourceMappingURL=session-cookie-policy.d.mts.map