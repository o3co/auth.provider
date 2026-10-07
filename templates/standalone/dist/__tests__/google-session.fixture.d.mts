import { type FederationTokenStore, type FederationTokens, type SessionFederationIndex, type UserSessionStore } from "@o3co/auth-provider-core";
import { type GoogleProviderConfig } from "@o3co/auth-provider-federation-google";
import express from "express";
export declare const ISSUER = "https://auth.test";
/** The one client: first-party, allowed federation tokens, one post-logout URI registered. */
export declare const CLIENT_ID = "rp";
export declare const REGISTERED_POST_LOGOUT_REDIRECT_URI = "https://rp.example/signed-out";
/** The Google client the adapter is configured with. */
export declare const GOOGLE_CLIENT_ID = "google-client";
/**
 * `"shipped"`: Google switched on the way an operator does, through its
 * environment variables and the template's own configuration bridge — which
 * has no setting for an end-session endpoint or a `fetch`. Otherwise the
 * adapter's configuration beyond its credentials, composed with
 * `googleFederationModule` directly.
 */
export type GoogleWiring = "shipped" | Omit<GoogleProviderConfig, "clientId" | "clientSecret" | "callbackURL">;
/**
 * A fresh id_token for the session, issued to the client: what an RP — or
 * anyone holding an id_token of their own — presents as `id_token_hint`.
 */
export declare const idTokenHint: (sid: string) => string;
/**
 * An access token for the session as the authorization-code grant issues it
 * to the client: `azp`, `sid` and a refresh-token `family_id`. The `session`
 * grant's token names no family, and the federation token route asks for one.
 */
export declare const accessTokenWithFamily: (sid: string) => string;
export interface GoogleSession {
    readonly app: express.Express;
    readonly sid: string;
    /** The access token the `session` grant minted for the session; it carries `azp`. */
    readonly accessToken: string;
    readonly userSessionStore: UserSessionStore;
    readonly sessionFederationIndex: SessionFederationIndex;
    readonly federationTokenStore: FederationTokenStore;
    readonly dispose: () => Promise<void>;
}
/**
 * Boots the deployment, signs alice in with her password, and links Google to
 * her session as a federated sign-in would: the session's federation index
 * names it and the token store holds `tokens`.
 */
export declare function signInLinkedToGoogle(options: {
    readonly google: GoogleWiring;
    readonly tokens: FederationTokens;
}): Promise<GoogleSession>;
//# sourceMappingURL=google-session.fixture.d.mts.map