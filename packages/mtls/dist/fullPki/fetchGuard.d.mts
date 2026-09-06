/**
 * A deliberately small HTTP client for fetching revocation material, with the
 * limits that make fetching a URL out of a certificate safe to do at all.
 *
 * ### Why this file exists
 *
 * Revocation checking means taking a URL from an X.509 extension and asking
 * this process to retrieve it. That is a server-side request forgery sink in
 * the classic shape: the request is made by us, from inside the network the
 * auth server lives in, to a destination named by someone else. A CRL
 * distribution point reading `http://169.254.169.254/latest/meta-data/` does
 * not have to return a parseable CRL to be useful to an attacker — the
 * request itself is the payload.
 *
 * Two controls bound it, and they are layered:
 *
 *  1. **Only a validated path may cause a fetch.** The caller
 *     (`validate.mts`) runs path validation to completion *before* reading
 *     any distribution point, so the URL always comes from a certificate that
 *     already chains to a trust anchor this deployment configured. A random
 *     client certificate cannot drive an outbound request.
 *  2. **A host allowlist**, enforced here. Layer 1 makes the URL come from a
 *     CA the operator trusts; this layer means trusting a CA to issue
 *     certificates is not the same as trusting it to choose destinations
 *     inside the operator's network. It is the same separation
 *     `oauth.mtls.trusted-proxies` draws for forwarded certificate headers,
 *     and it is required rather than defaulted for the same reason.
 *
 * On top of those: no redirects (a redirect is a second destination that
 * neither layer vetted), a byte cap read incrementally so a hostile responder
 * cannot exhaust memory before the check fires, a wall-clock timeout, and no
 * credentials.
 *
 * ### Why a bespoke client rather than the platform default
 *
 * `fetch` follows redirects, has no size limit, and has no notion of an
 * allowlist. Every one of those defaults is wrong here, and each is wrong in
 * a direction that fails open.
 */
/** Why a fetch did not produce bytes. Values are stable — audit logs read them. */
export type FetchRejection = "scheme_not_allowed" | "host_not_allowed" | "url_unparseable" | "url_has_credentials" | "redirect_refused" | "http_error" | "response_too_large" | "timeout" | "network_error";
export type FetchOutcome = {
    readonly ok: true;
    readonly bytes: Uint8Array;
} | {
    readonly ok: false;
    readonly reason: FetchRejection;
    readonly detail: string;
};
export interface GuardedFetchOptions {
    /**
     * Hosts this deployment will retrieve revocation material from. Each entry
     * is `host` or `host:port`, matched case-insensitively against the URL's
     * authority. An entry without a port matches any port. An IPv6 literal may
     * be written bracketed (`[::1]`, `[::1]:8080`) or, without a port, bare
     * (`::1`), expanded or compressed.
     *
     * Never empty: an empty allowlist would mean "any destination", and the
     * module refuses that at boot rather than accepting it here.
     */
    readonly allowedHosts: readonly string[];
    readonly timeoutMs: number;
    readonly maxBytes: number;
    /** Injected in tests. Defaults to the global `fetch`. */
    readonly fetchImpl?: typeof globalThis.fetch;
}
export type GuardedFetch = (url: string) => Promise<FetchOutcome>;
export declare const createGuardedFetch: (options: GuardedFetchOptions) => GuardedFetch;
//# sourceMappingURL=fetchGuard.d.mts.map