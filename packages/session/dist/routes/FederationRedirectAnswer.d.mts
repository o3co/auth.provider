/**
 * The federation routes' answers that rest on a provider's redirect policy:
 * the callback's last answer, for the login and the link alike (the redirect
 * the policy resolves from the start's `redirectTo`), and the one answer for
 * a provider with no policy, which the start gives too.
 */
import type { FederationProvider, Logger } from "@o3co/auth-provider-core";
import type { Response } from "express";
import type { FederationRouterContext } from "./FederationContext.mjs";
/**
 * A provider with no redirect policy: a composition fault, `500
 * internal_error`, logged once as `federation_misconfigured` with `context`.
 */
export declare const answerNoRedirectPolicy: (res: Response, log: Logger, context?: Readonly<Record<string, unknown>>) => void;
/**
 * Answer with the provider's policy's redirect. A provider with no policy is
 * a composition fault, `500`; a policy's refusal is answered in its words,
 * held to RFC 6749's characters (`refusalEnvelope`).
 */
export declare const redirectAfterCallback: (ctx: Pick<FederationRouterContext, "federationRedirectPolicyResolver">, provider: FederationProvider, redirectTo: string | undefined, res: Response, log: Logger) => void;
//# sourceMappingURL=FederationRedirectAnswer.d.mts.map