/**
 * `federation.grant.token.denied` for the exits the handler never reaches
 * (#593, D18).
 *
 * The token route's denial audits are supposed to cover everything that
 * happens before core is called: a body that would not parse, an
 * authentication that failed, this provider's own throttle, a limiter that is
 * down. Three of those four are decided by *middleware*, which answers and
 * ends the response — so a handler emitting them was emitting only the one it
 * could see, and every refused credential and throttled attempt stayed outside
 * the trail. Review found it.
 *
 * So the hook sits at the front of the chain and watches the response instead:
 * if it finished with a failure and the handler never ran, this is the event
 * for it. The outcome is read from the body the middleware wrote — the error
 * code, which is a fixed identifier — and never from its description, which
 * can carry what a limiter or a repository said.
 *
 * It names no client. Before authentication there is a Basic username and an
 * assertion `iss` on the request and neither has been verified; after a
 * failure there is no client at all.
 */
import type { RequestHandler, Response } from "express";
import { type FederationGrantAuditBridgeOptions } from "./audit.mjs";
import type { FederationGrantBackground } from "./background.mjs";
/** Called by a handler: from here on, the denial is the handler's to emit. */
export declare function markHandlerReached(res: Response): void;
export interface DenialAuditOptions extends FederationGrantAuditBridgeOptions {
    readonly background: FederationGrantBackground;
}
/**
 * The hook, for one route.
 *
 * `operation` decides which event a refusal becomes: the token route's
 * denials and the revoke route's are counted separately, because a credential
 * that was not handed out and a credential that is still live are opposite
 * facts.
 */
export declare function createRouteDenialAudit(options: DenialAuditOptions): RequestHandler;
//# sourceMappingURL=denialAudit.d.mts.map