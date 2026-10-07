import type { AppConfig } from "@o3co/auth-provider-core";
export interface BackchannelPeer {
    /** The endpoint, `http://127.0.0.1:<port>/logout`. */
    readonly uri: string;
    /** Each `logout_token` posted to it, in order. */
    readonly tokens: readonly string[];
    close(): Promise<void>;
}
/** A loopback back-channel endpoint answering `status` to every POST. */
export declare function backchannelPeer(status?: number): Promise<BackchannelPeer>;
/** `config` with loopback listed in `core.outbound.internalHosts`, so a `BackchannelPeer` is reachable. */
export declare const withLoopbackRelyingParties: (config: AppConfig) => AppConfig;
//# sourceMappingURL=backchannel-peer.fixture.d.mts.map