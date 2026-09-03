/**
 * `grant_type=urn:ietf:params:oauth:grant-type:device_code` — RFC 8628 §3.4,
 * §3.5 (#298).
 *
 * The device polls here until its user answers somewhere else. Almost all of
 * this handler is about answering *precisely enough*: RFC 8628 defines four
 * error codes for four different states, and a client library's whole control
 * flow is built on telling them apart.
 *
 *   - `authorization_pending` — keep polling, nothing has happened.
 *   - `slow_down` — keep polling, but you are going too fast. §3.5: "the
 *     interval MUST be increased by 5 seconds for this and all subsequent
 *     requests".
 *   - `access_denied` — stop; the user said no.
 *   - `expired_token` — stop; the window closed.
 *
 * Collapsing any pair of these into `invalid_grant` turns a client that would
 * have shown "you denied this on your phone" into one that retries forever.
 *
 * ### Where the interval is enforced
 *
 * In the store, not here. The check and the state change have to be one
 * operation — see `DeviceCodeStore.poll` — and a handler that read the record,
 * compared timestamps, and wrote back would let two concurrent polls both pass
 * the gate.
 *
 * ### Client binding
 *
 * The device code is issued to one client and only that client may redeem it.
 * A device code leaked to another registered client would otherwise be
 * redeemable by it, converting a leak into a full impersonation of the user's
 * approval. The check reads the authenticated client identity rather than the
 * body — the body is attacker-controlled, and reading it here would be the
 * same defect the session grant fixed in #295.
 */
import type { DeviceCodeStore, GrantHandler, KeyStore } from "@o3co/auth-provider-core";
export interface DeviceCodeGrantOptions {
    readonly store: DeviceCodeStore;
    readonly keyStore: KeyStore;
    readonly accessTokenExpiresIn: number;
    readonly logger?: {
        warn(obj: Record<string, unknown>, msg: string): void;
    };
    readonly now?: () => number;
}
export declare const createDeviceCodeGrant: (options: DeviceCodeGrantOptions) => GrantHandler;
//# sourceMappingURL=grant.d.mts.map