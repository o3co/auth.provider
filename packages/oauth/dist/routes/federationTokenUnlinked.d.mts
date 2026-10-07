import type { Response } from "express";
import type { FederationTokenContext } from "./federationTokenContext.mjs";
/**
 * The answer for a record that is missing, or that a store judging its
 * records would have answered as missing.
 */
export declare const answerUnlinkedRecord: (ctx: Pick<FederationTokenContext, "res" | "name">) => Response;
//# sourceMappingURL=federationTokenUnlinked.d.mts.map