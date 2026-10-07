/**
 * The end-user: the login check before any lookup, what session admission's
 * verdict is answered with, and the verified-email requirement. An outage is
 * `temporarily_unavailable` on the redirect URI, never the login page.
 */
import { type Admission, type SessionClaim, type UserSession } from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import { type PromptDirective } from "./authorizeAsk.mjs";
import { type AuthorizeContext, type AuthorizeHandlerOptions } from "./authorizeContext.mjs";
import type { ReauthAskStore } from "./reauthAsk.mjs";
/**
 * The login check, before any lookup: an unauthenticated browser is sent to
 * the login page unless the request names `prompt=none`, with the login ask
 * recorded when it names `prompt=login`. Returns the cookie's claim, or
 * `null` once the browser has been sent.
 */
export declare const checkLogin: (req: Request, res: Response, opts: Pick<AuthorizeHandlerOptions, "login" | "logger">, issuerOrigin: string, askStore: ReauthAskStore | undefined) => Promise<SessionClaim | null>;
/** Refuses `prompt=none` from a browser with no logged-in session. */
export declare const checkPromptNoneHasSession: (ctx: AuthorizeContext, prompt: PromptDirective, claim: SessionClaim) => boolean;
/**
 * Acts on the admission, or returns `null` once answered. An outage is
 * `temporarily_unavailable` on the validated redirect URI — never the login
 * page, whose forwarding of signed-in users would loop. A dead or
 * unauthenticated session gets a new login; `reauthenticate` gets one login
 * trip (`reauthenticate`). For the outcomes that carry a
 * session, freshness (`max_age`, `prompt=login`) is decided first, so
 * `prompt=none` with a stale `max_age` is `login_required` whatever the
 * verdict; then `unmet` is refused, `step_up` is a trip, and `admitted`
 * proceeds with the `acr` the session met, once its `authTime` can be read
 * against the clock (`authTimeReadable`).
 */
export declare const decideOnAdmission: (ctx: AuthorizeContext, admission: Admission, prompt: PromptDirective, maxAge: number | undefined, requested: readonly string[], askStore: ReauthAskStore | undefined) => Promise<Decided | null>;
/** What `decideOnAdmission` hands on for a session it lets through. */
interface Decided {
    readonly session: UserSession | null;
    readonly acr: string | undefined;
    /** What the code records of how the session had authenticated: the admission's. */
    readonly codeFields: Extract<Admission, {
        readonly outcome: "admitted";
    }>["codeFields"];
    /** The session is fresh because of the login the presented ask asked for. */
    readonly freshByAsk: boolean;
}
export declare const checkEmailVerified: (ctx: AuthorizeContext) => Promise<boolean>;
export {};
//# sourceMappingURL=authorizeSession.d.mts.map