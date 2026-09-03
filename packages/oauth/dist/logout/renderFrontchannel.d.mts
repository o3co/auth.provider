import type { Logger } from "@o3co/auth-provider-core";
export interface FrontchannelRP {
    readonly clientId: string;
    readonly frontchannelLogoutUri?: string;
    /** Defaults to `true` — append sid so RPs can correlate sessions. */
    readonly frontchannelLogoutSessionRequired?: boolean;
}
export interface RenderFrontchannelLogoutHtmlOptions {
    readonly rps: ReadonlyArray<FrontchannelRP>;
    readonly issuer: string;
    readonly sid: string;
    readonly postLogoutRedirectUri?: string;
    /** Defaults to 2000ms. */
    readonly redirectDelayMs?: number;
    /**
     * Optional logger for warning when an RP's frontchannelLogoutUri is invalid
     * and its iframe must be skipped. Falls back to `console` when omitted.
     */
    readonly logger?: Logger;
}
/**
 * Renders an OIDC Front-Channel Logout 1.0 HTML page: one hidden `<iframe>` per RP
 * that has a `frontchannelLogoutUri`. Each iframe URL carries `iss` and optionally
 * `sid` query parameters (sid included when `frontchannelLogoutSessionRequired`
 * is not explicitly `false`). When `postLogoutRedirectUri` is provided, appends
 * a `<script>` that redirects after `redirectDelayMs` to let iframes load.
 *
 * Pure function: does no I/O, returns a string. Callers MUST send with
 * `Content-Type: text/html; charset=utf-8`.
 */
export declare function renderFrontchannelLogoutHtml(opts: RenderFrontchannelLogoutHtmlOptions): string;
//# sourceMappingURL=renderFrontchannel.d.mts.map