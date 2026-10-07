import type { RequestHandler, Router } from "express";
type ExpressLike = {
    Router: () => Router;
    json: () => RequestHandler;
    urlencoded: (opts: {
        extended: boolean;
    }) => RequestHandler;
};
export interface OidcConfigRouterOptions {
    issuer: string;
    signingAlgs: ReadonlyArray<string>;
    /**
     * When true, advertise end_session_endpoint and backchannel/frontchannel logout_supported
     * fields in the discovery response. Must be set explicitly — defaults to false so that
     * callers who use this router directly (bypassing oauthModule) do not accidentally
     * advertise logout support without mounting the logout route.
     * oauthModule sets this to the computed `!!stores && !!issuer` expression.
     */
    logoutSupported?: boolean;
}
export declare function createRouter(express: ExpressLike, opts: OidcConfigRouterOptions): Router;
export {};
//# sourceMappingURL=OpenidConfiguration.d.mts.map