/**
 * The body the session routes answer a redirect policy's refusal with.
 *
 * A policy — this package's allowlist validator, or one a module contributes
 * — names the status, the code and the description. Core's `errorEnvelope`
 * holds the text to RFC 6749's characters and answers a malformed code
 * `server_error`, which is right under a 5xx; under the 4xx a refusal almost
 * always is, it would make a contradictory `400 server_error`. The refusal is
 * still a verdict on the client's `redirect_to`, so a malformed code under a
 * 4xx is answered `invalid_request` here, as `tokenBindingMw` and
 * `/oauth/token`'s grant-policy deny do, and logged.
 *
 * A 5xx is not a verdict on the client: the policy says the server cannot
 * answer — the default policy's `500 misconfiguration` when neither
 * `authCallbackUrl` nor `clientUrl` covers the callback, or a contributed
 * policy's own failure. It is relayed as the policy worded it and logged once
 * at error level as `redirect_policy_server_fault`, with the status and the
 * policy's code and description sanitised and capped. A 4xx is not logged.
 */
import { type ErrorEnvelope, type Logger } from "@o3co/auth-provider-core";
/** What a redirect policy refuses with (`FederationResult`'s failure). */
export interface PolicyRefusal {
    readonly status: number;
    readonly error: string;
    readonly errorDescription: string;
}
/**
 * @param context — fields the log lines carry beside the refusal's own, such
 *   as the federation's `provider` where the logger does not already bind it.
 */
export declare function refusalEnvelope(refusal: PolicyRefusal, logger: Logger, context?: Readonly<Record<string, unknown>>): ErrorEnvelope;
//# sourceMappingURL=refusalEnvelope.d.mts.map