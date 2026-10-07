import type { Response } from "express";
import type { FederationTokenCaller, FederationTokenContext } from "./federationTokenContext.mjs";
import type { DisclosableToken } from "./federationTokenDisclosure.mjs";
/**
 * Hands `token` to the caller; only the disclosure check produces one.
 * The floor is judged before the success is audited, and again where
 * `expires_in` is computed, last, just before the answer is sent: time spent
 * before it (the audit call included) is not counted as lifetime left, and a
 * `200` never carries `expires_in: 0`.
 */
export declare const answerToken: (ctx: FederationTokenContext, caller: FederationTokenCaller, token: DisclosableToken, refreshed: boolean) => Promise<Response>;
//# sourceMappingURL=federationTokenSuccess.d.mts.map