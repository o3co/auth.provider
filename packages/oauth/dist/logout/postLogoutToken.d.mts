/**
 * POSTs one logout_token to `uri` as OIDC Back-Channel Logout 1.0 §2.5 has
 * it, a form body, through `options.fetchImpl` alone, under one deadline
 * (default 5000ms): the relying party's answer's status, its body left unread
 * and cancelled, or the rejection of a request that did not complete or that
 * the fetch refused.
 */
export declare function postLogoutToken(uri: string, token: string, options: {
    readonly fetchImpl: typeof fetch;
    readonly timeoutMs?: number;
}): Promise<{
    readonly ok: boolean;
    readonly status: number;
}>;
//# sourceMappingURL=postLogoutToken.d.mts.map