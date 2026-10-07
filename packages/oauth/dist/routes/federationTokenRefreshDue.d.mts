/**
 * Whether a stored token is refreshed before it is handed on: one with no
 * finite expiry only when the record holds a refresh token, so its answer is
 * stored with an end, capped at the maximum; one that ends within the refresh
 * buffer is, unless it is known to be obtained less than half its lifetime
 * ago and has at least the refresh floor left. That rule only ever delays a refresh: an
 * `obtainedAt` that is `undefined`, or that core's `judgeHeldUpstreamToken` does
 * not believe (dated more than the floor ahead of this replica's clock, or
 * not before its own end), leaves the buffer rule alone. It reads the
 * record's instants on this replica's clock, so it assumes replicas' clocks
 * agree to within the floor.
 */
import { type FederationTokens } from "@o3co/auth-provider-core";
import type { FederationTokenContext } from "./federationTokenContext.mjs";
export declare const refreshIsDue: (ctx: Pick<FederationTokenContext, "refreshBufferMs">, tokens: Pick<FederationTokens, "expiresAt" | "obtainedAt" | "refreshToken">) => boolean;
//# sourceMappingURL=federationTokenRefreshDue.d.mts.map