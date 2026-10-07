/**
 * Whether an upstream token may be handed to the caller, and the refusal when
 * it may not: this route delegates by value, so only `Bearer` goes out; any
 * other type is `502 upstream_token_ineligible`, audited, with `Retry-After`.
 * The check alone marks a token `DisclosableToken`, the only kind the success
 * answer takes.
 */
import { type FederationTokens } from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";
declare const disclosableBrand: unique symbol;
/** A token whose type `isDisclosable` judged: nothing else produces one. */
export type DisclosableToken = Pick<FederationTokens, "accessToken" | "expiresAt" | "scope"> & {
    readonly [disclosableBrand]: true;
};
/** Whether `token` may be handed to the caller, by its type (`mayDiscloseTokenType`). */
export declare const isDisclosable: <T extends Pick<FederationTokens, "accessToken" | "expiresAt" | "scope" | "tokenType">>(token: T) => token is T & DisclosableToken;
/**
 * Refuses a token whose type this route may not delegate. `502`: what
 * came back from the upstream cannot be handed on, through no fault of
 * the caller or this provider (the offline-delegation route answers the
 * same). The named type goes to the audit sink, sanitised, not to the
 * caller. `Retry-After` because the condition is not transient.
 */
export declare const refuseUndisclosableTokenType: (ctx: FederationTokenContext, caller: FederationTokenCaller, named: unknown) => Response;
export {};
//# sourceMappingURL=federationTokenDisclosure.d.mts.map