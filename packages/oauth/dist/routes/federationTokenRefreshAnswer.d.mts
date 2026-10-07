/**
 * Reading an adapter's refresh answer: each field read once behind a guard,
 * its lifetime judged through core's reading and capped at the route's
 * maximum, its token type judged, and the rules that bound the scope it
 * names. Nothing here writes, logs or answers, and no lifetime field makes it throw.
 */
import { type FederationTokens, type RefreshedTokens } from "@o3co/auth-provider-core";
/** No refreshed token is accepted with less than this left (ms) when its answer is read. */
export declare const REFRESH_FLOOR_MS = 1000;
/**
 * How a refresh answer names the token's scope. `narrowedScope` bounds it by
 * `granted`, what the user consented to at link time: RFC 6749 §6 bounds a
 * refresh by the original grant, not by the token it replaces, so judging
 * against the current scope would make a narrowing permanent. A record
 * without `granted` is judged against its current scope.
 *
 * - narrower than the bound: recorded (§6 allows narrowing);
 * - named but unusable: the stored value stands — learning nothing is never
 *   a reason to widen;
 * - omitted: the bound itself — no `scope` is sent upstream, and §5.1 lets
 *   the answer omit it only when it matches the request, i.e. the grant;
 * - wider than the bound: not recorded; the stored value stands (§6).
 *
 * Reading silence as the bound can over-report after an upstream narrows,
 * but never beyond consent, and no authorization decision here reads the
 * field. Answers are canonical. The sibling rule for grants that outlive a
 * session is core's `scopesWithin` / `consentedScopes`.
 */
type AnsweredScope = 
/** The upstream named no scope at all. */
{
    readonly kind: "omitted";
}
/** It named one, and it parses. */
 | {
    readonly kind: "named";
    readonly value: string;
}
/** It named something this route could not use: unreadable, or not a scope. */
 | {
    readonly kind: "unusable";
};
export declare const narrowedScope: (answered: AnsweredScope, stored: string | undefined, granted: string | undefined) => string | undefined;
/**
 * A refresh answer as `readRefreshAnswer` read it, and how it judged it. Every
 * verdict on the answer is here, so the code that acts on it judges nothing.
 */
export interface RefreshReading {
    /** The answered access token when it is usable; `undefined` is a failed refresh. */
    readonly accessToken: string | undefined;
    /** The answered refresh token when it is usable, whether or not it differs from the stored one. */
    readonly rotatedRefreshToken: string | undefined;
    /** The answered id token when it is usable. */
    readonly rotatedIdToken: string | undefined;
    /** The lifetime the record carries next, or the verdict that refused it. */
    readonly lifetime: RefreshedLifetime;
    readonly tokenTypeIsBroken: boolean;
    /** The type the record carries next. */
    readonly nextTokenType: string | undefined;
    /** How the answer named the scope, for `narrowedScope`. */
    readonly answeredScope: AnsweredScope;
}
/** What the route asks of a refresh answer's lifetime. */
export interface RefreshLifetimePolicy {
    /** When the refresh was asked for (epoch ms): an `expiresIn` counts from it. */
    readonly calledAt: number;
    /** The longest a refreshed token is stored for (ms), counted from when the answer is read. */
    readonly maxTokenLifetimeMs: number;
}
/**
 * The lifetime a refresh answer gives the record: always a finite end, or the
 * verdict that refused the answer. Nothing accepted is stored without an end.
 */
export type RefreshedLifetime = {
    readonly accepted: true;
    /** The derived end, capped at the maximum. */
    readonly expiresAt: Date;
    /**
     * The start of the refresh call; `undefined` for an end the upstream
     * stated only as an instant, which is on its own clock and so is never
     * aged. With the cap, `expiresAt − obtainedAt` may exceed the maximum
     * by the call's duration.
     */
    readonly obtainedAt: Date | undefined;
} | {
    readonly accepted: false;
    /** Core's verdict, `unreadable` for a field whose getter threw, `unrecognised` for one this route does not know. */
    readonly verdict: "unreadable" | "malformed" | "contradictory" | "spent" | "unrecognised";
};
/**
 * Reads `refreshed` once. `currentTokens` is the freshest snapshot of the
 * record, whose type stands when the answer names none.
 */
export declare const readRefreshAnswer: (refreshed: RefreshedTokens, currentTokens: FederationTokens, policy: RefreshLifetimePolicy) => RefreshReading;
export {};
//# sourceMappingURL=federationTokenRefreshAnswer.d.mts.map