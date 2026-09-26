export interface Client {
    clientId: string;
    clientSecret: string;
    allowedRedirectUris: string[];
    allowedScopes: string[];
    postLogoutRedirectUris?: string[];
    backchannelLogoutUri?: string;
    backchannelLogoutSessionRequired?: boolean;
    frontchannelLogoutUri?: string;
    frontchannelLogoutSessionRequired?: boolean;
    /**
     * When true, this client MAY call POST /oauth/federation/:name/token to
     * retrieve the user's upstream federation access_token. Deny-by-default
     * (deny-by-absence); must be explicitly opted in per client.
     *
     * Why default false: federation access_tokens grant access to the user's
     * external resources (Google Calendar, GitHub API, etc.) — high blast
     * radius. Opt-in prevents accidentally granting this power to a generic
     * OAuth client registration that only needs auth.
     */
    allowedAzpForFederationToken?: boolean;
}
export interface User {
    id: string;
    username: string;
    [key: string]: unknown;
}
export interface CodeData {
    code_challenge?: string;
    code_challenge_method?: string;
    redirect_uri?: string;
    nonce?: string;
    sid?: string;
}
export interface Code extends CodeData {
    code: string;
    expiresIn?: number;
    grantedScope?: readonly string[];
    grantedAudience?: readonly string[];
}
//# sourceMappingURL=types.d.mts.map