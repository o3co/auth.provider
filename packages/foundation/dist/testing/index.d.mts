/**
 * `@o3co/auth-provider-foundation/testing`: what a test uses to configure
 * this package's modules. Test code imports it; production code never does.
 */
import { FOUNDATION_MFA_FACTOR_STORE_SECTION, type FoundationMfaFactorStoreUrls } from "../mfa/section.mjs";
/** The Store URLs the `"http"` user adapter's builder reads (`registerBuiltinAdapters`). */
declare const USER_REPOSITORY_URL_KEYS: readonly ["authenticateUrl", "authenticateByTokenUrl", "linkFederatedIdentityUrl", "findSubjectByFederatedIdentityUrl", "markMfaEnrolledUrl"];
/** The user repository's Store URLs, as the `"http"` builder names them. */
export type FoundationUserRepositoryUrls = Readonly<Record<(typeof USER_REPOSITORY_URL_KEYS)[number], unknown>>;
/**
 * The `foundation-mfa-factor-store` section as a configuration fragment to
 * lay over a test's configuration: the four URLs `urls` holds — a fake
 * Store's `urls` included, its other endpoints left behind — and `extra`
 * as given.
 */
export declare function foundationMfaFactorStoreConfig(urls: Partial<Readonly<Record<keyof FoundationMfaFactorStoreUrls, unknown>>>, extra?: Readonly<Record<string, unknown>>): {
    readonly [FOUNDATION_MFA_FACTOR_STORE_SECTION]: Readonly<Record<string, unknown>>;
};
/**
 * The user repository's `http` block, as the `"http"` builder reads it: the
 * Store URLs `urls` holds — a fake Store's `urls` included, its MFA factor
 * endpoints left behind — and `extra` as given. A test hands it to the
 * `"http"` builder, or to `foundationMfaFactorStoreModule` as its
 * `storeTransport`.
 */
export declare function foundationUserRepositoryHttpConfig(urls: Partial<FoundationUserRepositoryUrls>, extra?: Readonly<Record<string, unknown>>): Readonly<Record<string, unknown>>;
export {};
//# sourceMappingURL=index.d.mts.map