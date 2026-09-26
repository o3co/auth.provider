/**
 * A client's federation-grant registration list, read defensively (#593, D9).
 *
 * `allowedFederationGrantConnections` and `federationGrantRedirectUris` are
 * fields of a `Client` a `ClientRepository` answers. `ClientRepository` is a
 * port: the bundled repository validates both against the registration schema,
 * and a deployment's own repository — the whole reason the port exists —
 * validates nothing this package can see. D9 says to check the authenticated
 * record before using its new fields, and review named what happens
 * otherwise: a repository that answers a comma-joined string turns a
 * membership check into a substring match, where
 * `"calendar,mail".includes("cal")` is `true` and a client is allowed a
 * connection nobody granted it, or a redirect URI that is merely a prefix of
 * the registered one.
 *
 * So anything that is not an array is read as an empty list — the same thing
 * absence means: nothing is allowed — and an array keeps only its strings.
 * One reader for every place the fields are judged: lodging, the consent
 * page's re-check, and the token and status routes.
 */
export declare function federationGrantAllowlist(value: unknown): readonly string[];
//# sourceMappingURL=allowlist.d.mts.map