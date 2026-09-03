import { type KeyStore, type Logger } from "@o3co/auth-provider-core";
export interface BroadcastRP {
    readonly clientId: string;
    readonly backchannelLogoutUri?: string;
    /**
     * Whether the RP requires `sid` in the logout_token for session correlation.
     * Defaults to `true` — include sid unless explicitly set to `false`.
     */
    readonly backchannelLogoutSessionRequired?: boolean;
}
export interface BroadcastBackchannelLogoutOptions {
    readonly rps: ReadonlyArray<BroadcastRP>;
    /** Issuer URL of this auth provider. */
    readonly issuer: string;
    /** Subject identifier of the user being logged out. */
    readonly sub: string;
    /** Session ID being terminated. Included in each logout_token when the RP requires sid. */
    readonly sid: string;
    readonly keyStore: KeyStore;
    /** Override for unit tests. Defaults to the global `fetch`. */
    readonly fetchImpl?: typeof fetch;
    /** Per-request timeout in milliseconds. Defaults to 5000ms. */
    readonly timeoutMs?: number;
    /** Optional structured logger. Defaults to `console`. */
    readonly logger?: Logger;
}
/**
 * Best-effort parallel POST of OIDC Back-Channel Logout 1.0 logout_token to each RP's
 * `backchannelLogoutUri`. Never throws; 4xx/5xx/network/timeout failures are logged via
 * `opts.logger ?? console`. RPs without a `backchannelLogoutUri` are skipped.
 */
export declare function broadcastBackchannelLogout(opts: BroadcastBackchannelLogoutOptions): Promise<void>;
//# sourceMappingURL=broadcastBackchannel.d.mts.map