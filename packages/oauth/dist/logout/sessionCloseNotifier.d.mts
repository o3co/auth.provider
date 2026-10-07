/**
 * The session-close notifier oauth contributes to core's session lifecycle:
 * one OIDC Back-Channel Logout token per notice, posted to the relying
 * party's `backchannel_logout_uri` as its registration reads when the notice
 * is sent, through the fetch it is built with alone (core's outbound fetch,
 * under `core.outbound`). A notice is settled — resolved — once delivered, or
 * when there is nowhere to send it (no URI, no registration), the relying
 * party refused it for good, or the fetch refused the destination or the
 * answer (a redirect among them, never followed); it rejects only when it is
 * worth sending again, so the lifecycle keeps the work pending: the registry
 * or the key store could not answer, the request did not complete, or the
 * answer was 408, 429 or a 5xx.
 *
 * Every token carries the session's `sid` unless the relying party declined
 * one (`backchannel_logout_session_required: false`), whatever closed it.
 */
import { type ClientRepository, type EventLogger, type KeyStore, type SessionCloseNotifier } from "@o3co/auth-provider-core";
export interface SessionCloseNotifierOptions {
    readonly clientRepository: ClientRepository;
    readonly keyStore: KeyStore;
    /** This provider's issuer, the logout token's `iss`. */
    readonly issuer: string;
    /**
     * The fetch every POST goes through: core's
     * `createOutboundFetch({ policy, source: "registration" })` over the
     * `outboundPolicy` slot, so `core.outbound` applies. Anything else
     * replaces that policy.
     */
    readonly fetchImpl: typeof fetch;
    /** The deadline of one delivery, in milliseconds. Defaults to 5000. */
    readonly timeoutMs?: number;
    /** Where a notice settled undelivered is said, at warn. */
    readonly logger?: Pick<EventLogger, "warn">;
}
export declare function createSessionCloseNotifier(options: SessionCloseNotifierOptions): SessionCloseNotifier;
//# sourceMappingURL=sessionCloseNotifier.d.mts.map