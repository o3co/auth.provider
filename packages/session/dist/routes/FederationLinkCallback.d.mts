/**
 * The link callback: a federated identity linked to the account of the
 * session the link start recorded, and the federation attached to that live
 * session. It never mints a session, and a half-attached federation is
 * rolled back.
 */
import { type FederationProvider, type Logger, type UserRepository } from "@o3co/auth-provider-core";
import type { Request, Response } from "express";
import type { LinkIntent } from "../federations/transaction.mjs";
import type { LinkedTokenLifetime } from "./FederationCallbackIdentity.mjs";
import type { FederationRouterContext } from "./FederationContext.mjs";
/**
 * The record's `tokenType` for what an adapter answered: the upstream's
 * spelling verbatim, even when it is not a token type, because the
 * disclosing route reads only an absent field as `Bearer` — erasing an
 * unusable value would turn a refusal into a 200. A non-string is recorded
 * as `""`, which that route also refuses.
 */
export declare const recordedTokenType: (named: unknown) => string | undefined;
/**
 * Link a federated identity to the account the browser is signed in as,
 * without minting a session. Reached only from an explicit `?link=1` start
 * whose envelope was verified like a login's. An identity resolving to
 * nobody asks the Store to link; to someone else is `409` (linking never
 * merges accounts); to this account links nothing new. The federation is
 * then attached to the live session (its upstream tokens under the current
 * `sid`, and a join through core's session lifecycle); no `UserSession` is
 * created and the session is not
 * regenerated. The session is admitted as `session.link_callback`; a
 * step-up is `login_required`, since the IdP's callback has no page to
 * return to.
 */
export declare const completeLink: (ctx: FederationRouterContext, provider: FederationProvider, profile: Awaited<ReturnType<FederationProvider["exchangeCode"]>>, lifetime: LinkedTokenLifetime, identityToken: string, resolved: Awaited<ReturnType<UserRepository["authenticateByToken"]>>, redirectTo: string | undefined, link: LinkIntent, req: Request, res: Response, log: Logger) => Promise<unknown>;
//# sourceMappingURL=FederationLinkCallback.d.mts.map