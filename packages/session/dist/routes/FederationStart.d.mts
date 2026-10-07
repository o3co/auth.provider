import type { Request, Response } from "express";
import type { FederationRouterContext } from "./FederationContext.mjs";
/** The start route's handler, over the router's context. */
export declare const createStartHandler: (ctx: FederationRouterContext) => (req: Request, res: Response) => Promise<unknown>;
//# sourceMappingURL=FederationStart.d.mts.map