/**
 * Which federation a callback request is for, and what it carries: an
 * installed provider reached by the one method its response mode uses (the
 * other is `405`, refused before any cookie is read), and its parameters
 * narrowed to string entries.
 */
import { type FederationProvider } from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import type { FederationRouterContext } from "./FederationContext.mjs";
/**
 * Narrow a callback's parameter bag (`req.query` or `req.body`) to its string
 * entries. Both are attacker-shapeable (repeats arrive as arrays, bodies can
 * nest), so `state` is only ever compared with a string or `undefined`, and
 * adapters get flat strings.
 */
export declare const readCallbackParams: (source: unknown) => Readonly<Record<string, string>>;
/**
 * The installed provider a callback names, reached by its response mode's
 * method: `query` by `GET`, `form_post` by `POST`. Answers `404` or `405` and
 * returns `null` otherwise.
 */
export declare const resolveCallbackProvider: (ctx: FederationRouterContext, source: "query" | "body", req: Request, res: Response) => FederationProvider | null;
//# sourceMappingURL=FederationCallbackRequest.d.mts.map