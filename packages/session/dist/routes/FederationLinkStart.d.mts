/**
 * The link start's checks, before any state is kept: the navigation came from
 * this site or a trusted origin, the Store can link, and the session cookie's
 * session is admitted as `session.link`. What it returns is the `sid` and
 * subject the callback links to.
 */
import { type FederationProvider } from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import type { LinkIntent } from "../federations/transaction.mjs";
import type { FederationRouterContext } from "./FederationContext.mjs";
/**
 * Check a `?link=1` start. Answers and returns `null` when the link cannot
 * succeed; otherwise returns the link intent the transaction records.
 */
export declare const checkLinkStart: (ctx: FederationRouterContext, provider: FederationProvider, req: Request, res: Response) => Promise<LinkIntent | null>;
//# sourceMappingURL=FederationLinkStart.d.mts.map