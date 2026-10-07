import type { Logger } from "@o3co/auth-provider-core";
/**
 * Why a front-channel logout URI was not used: `not-http` for a parsed
 * protocol other than `http:` / `https:`, `unparsable` for a value `URL`
 * cannot parse, `not-a-string` for a value of another type, `unreadable`
 * when reading the field threw.
 */
export type FrontchannelLogoutUriRefusal = "not-http" | "unparsable" | "not-a-string" | "unreadable";
/** Where the URI is used: logout, from an RP the session RP registry answers. */
export type FrontchannelLogoutUriSite = "logout";
/** What a front-channel logout URI is read from: a registered RP. */
export interface FrontchannelLogoutUriSource {
    readonly clientId?: unknown;
    readonly frontchannelLogoutUri?: unknown;
}
/** An RP's front-channel registration as read once: plain values, the URI checked. */
export interface UsableFrontchannelRP {
    readonly clientId: string;
    readonly frontchannelLogoutUri: string;
    readonly frontchannelLogoutSessionRequired: boolean | undefined;
}
/**
 * The RP's front-channel fields, each read once, when its URI may be used;
 * otherwise `undefined`. Absent (`undefined`, `null`, `""`) is silent.
 * Anything else must be a string whose parsed protocol is `http:` or
 * `https:`, on any host, the scheme rule core's client-record schema applies. A
 * refused value is one warn with the reason, never the value. Every read goes
 * through core's `guardedRead` and the warn is guarded: front-channel logout
 * is best-effort, so a refusal drops only this RP.
 *
 * Checked where it is used: an entry a custom session RP registry answers is
 * not read through core's client-record boundary, so nothing upstream holds
 * it to that rule. A session flag whose read throws skips the RP with one
 * `logout_frontchannel_iframe_skipped` warn, as an iframe that cannot be
 * built does. Never throws. Who renders from the answer reads nothing of the
 * RP again.
 */
export declare function usableFrontchannelRP(rp: FrontchannelLogoutUriSource & {
    readonly frontchannelLogoutSessionRequired?: unknown;
}, site: FrontchannelLogoutUriSite, logger: Pick<Logger, "warn">): UsableFrontchannelRP | undefined;
//# sourceMappingURL=frontchannelLogoutUri.d.mts.map