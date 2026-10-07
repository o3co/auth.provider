/**
 * Who the callback's user is: the authorization code exchanged with the
 * upstream IdP for its profile, the local account that profile's identity
 * resolves to, if any, and the lifetime its access token is recorded with.
 * Runs only on a state the callback retired.
 *
 * The lifetime is read once, through core's reading at a floor of 0 with no
 * cap. Finite with `expiresIn` stated: `obtainedAt` is the instant before the
 * exchange and `expiresAt` the reading's end. Otherwise: the adapter's
 * `expiresAt` and `obtainedAt` undefined. A lifetime that cannot be read, or an
 * `expiresAt` that is neither absent, `null` nor an instant, is a failed
 * exchange (502), as is an `authTime` core would not record (present but not
 * an instant at or after the epoch, or further ahead than
 * `DEFAULT_CLOCK_SKEW_MS`).
 */
import { type FederationProvider, type FederationTokens, type Logger, type UserRepository } from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { FederationRouterContext } from "./FederationContext.mjs";
/** The lifetime fields a link-time `FederationTokens` record carries. */
export type LinkedTokenLifetime = Pick<FederationTokens, "expiresAt" | "obtainedAt">;
/**
 * The upstream's profile, the identity token it names, the local account it
 * resolves to (`null` for none), the lifetime its access token is recorded
 * with, and the upstream's authentication time as core records it.
 */
export interface FederatedIdentity {
    readonly profile: Awaited<ReturnType<FederationProvider["exchangeCode"]>>;
    readonly identityToken: string;
    readonly user: Awaited<ReturnType<UserRepository["authenticateByToken"]>>;
    readonly lifetime: LinkedTokenLifetime;
    readonly upstreamAuthTime: Date | undefined;
}
/**
 * Exchange the callback's code and resolve the identity. Answers and returns
 * `null` on a refusal, an upstream failure or an outage.
 */
export declare const identifyFederatedUser: (ctx: FederationRouterContext, provider: FederationProvider, params: Readonly<Record<string, string>>, codeVerifier: string, nonce: string | undefined, res: Response, log: Logger) => Promise<FederatedIdentity | null>;
//# sourceMappingURL=FederationCallbackIdentity.d.mts.map