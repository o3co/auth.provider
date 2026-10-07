/**
 * The callback's state check, its security boundary: the ephemeral state read
 * from where the start kept it, `state` compared with it, and the state
 * retired before any async work. A request with no `state`, or a wrong
 * one, leaves the transaction in place: it is spent only once `state`
 * matches.
 */
import { type FederationProvider, type Logger } from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import type { FederationTransactionEnvelope } from "../federations/transaction.mjs";
import type { FederationRouterContext } from "./FederationContext.mjs";
/**
 * Read, check and retire the callback's ephemeral state. Answers and
 * returns `null` on a refusal or an outage; otherwise returns the envelope,
 * already retired.
 */
export declare const consumeCallbackState: (ctx: FederationRouterContext, provider: FederationProvider, params: Readonly<Record<string, string>>, req: Request, res: Response, log: Logger) => Promise<FederationTransactionEnvelope | null>;
//# sourceMappingURL=FederationCallbackState.d.mts.map