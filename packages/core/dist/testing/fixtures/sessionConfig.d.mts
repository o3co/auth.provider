/**
 * A copy of `config` whose session cookie (`session-store.name`,
 * `session-store.secure`) a plain-HTTP client keeps — not `Secure`, and named
 * without the `__Host-` prefix, which requires it — every other key kept;
 * `config` itself is left as it was.
 */
export declare function withInsecureSessionCookie<C extends {
    readonly "session-store": object;
}>(config: C): C;
/**
 * What {@link withFederation} writes of one federation: its callback URL, the
 * type that handles it, and client credentials a test may name.
 */
export interface FederationForTests {
    readonly callbackURL: string;
    /** The `federationTypes` key of the package that handles it. */
    readonly type: string;
    /** Default `<name>-client`. */
    readonly clientId?: string;
    /** Default `<name>-secret`. */
    readonly clientSecret?: string;
}
/** One enabled federation entry, as {@link withFederation} writes it. */
export interface FederationEntryForTests {
    readonly enabled: true;
    readonly type: string;
    readonly clientId: string;
    readonly clientSecret: string;
    readonly callbackURL: string;
}
/**
 * A copy of `config` whose `core.federations.<name>` is an enabled entry with
 * `entry`'s callback URL, type and client credentials, every
 * other federation and key of `core` and of `config` kept; `config` itself is
 * left as it was.
 */
export declare function withFederation<C extends object>(config: C, name: string, entry: FederationForTests): C & {
    readonly core: {
        readonly federations: Readonly<Record<string, FederationEntryForTests>>;
    };
};
//# sourceMappingURL=sessionConfig.d.mts.map