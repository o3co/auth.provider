/**
 * Consent for a client that is not first-party: the user's recorded consent
 * covers the request, or the request is parked under a session-bound challenge
 * and sent to the consent page. A store outage is `temporarily_unavailable`.
 */
import { type PublicClient } from "@o3co/auth-provider-core";
import type { PromptDirective } from "./authorizeAsk.mjs";
import { type AuthorizeContext } from "./authorizeContext.mjs";
/**
 * Consent for a client that is not an explicit `firstParty: true`. Without
 * it, a forced navigation from an attacker's page would make a logged-in
 * victim's browser mint a code for the attacker's chosen `code_challenge`.
 * The user is asked on the deployment's own page and the answer recorded, so
 * covered requests are not asked again. Runs after every request-shape check
 * (no consent for a request that would fail anyway) and before the policy.
 */
export declare const checkConsent: (ctx: AuthorizeContext, client: PublicClient, scopes: readonly string[], prompt: PromptDirective) => Promise<boolean>;
//# sourceMappingURL=authorizeConsent.d.mts.map