/** What {@link oauthConfigForTests} lays over the section's defaults. */
export interface OAuthConfigForTestsOptions {
    /** `oauth.jwt.issuer`; core's test issuer unless given. */
    readonly issuer?: string;
    /** `oauth.accessToken.defaultExpiresIn`, in seconds; 3600 unless given. */
    readonly accessTokenExpiresIn?: number;
    /** `oauth.refreshToken.expiresIn`, in seconds; 86400 unless given. */
    readonly refreshTokenExpiresIn?: number;
    /**
     * `oauth.authorize.acrValues`: each acr this deployment vouches for, with
     * the `amr` values that satisfy it (one list, or alternatives); left
     * unstated, which reads as no acr values, unless given.
     */
    readonly acrValues?: Readonly<Record<string, readonly string[] | readonly (readonly string[])[]>>;
}
/**
 * The `oauth` section, as a configuration fragment to lay over a
 * configuration: the keys core's testing builder carries (`jwt`,
 * `accessToken`, `refreshToken`, `revocation`: the ones core reads), and this
 * package's own required and page keys (`oidcMode`, `consentPage`,
 * `clientIdMetadataDocuments`) at `config/reference.conf`'s defaults, with
 * `options` laid over them. A fresh object each call.
 */
export declare function oauthConfigForTests(options?: OAuthConfigForTestsOptions): {
    oauth: {
        oidcMode: string;
        consentPage: {
            url: string;
        };
        clientIdMetadataDocuments: {
            enabled: boolean;
        };
        authorize?: {
            acrValues: Record<string, string[] | string[][]>;
        } | undefined;
        jwt: {
            issuer: string;
        };
        accessToken: {
            defaultExpiresIn: number;
        };
        refreshToken: {
            expiresIn: number;
        };
        revocation: {
            accessToken: string;
            subject: string;
        };
    };
};
//# sourceMappingURL=index.d.mts.map