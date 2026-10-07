/**
 * The module that keeps a subject's MFA factors in the Store:
 * `foundation-mfa-factor-store` provides `mfaFactorStore` as an
 * `HttpMfaFactorStore`, built at boot whether or not anything requires it.
 *
 * Guarantees: the section's four URLs are read first, so a composition that
 * installs the module with any of them unset refuses the boot; the Store's
 * credential, deadline and response cap are the Store transport settings the
 * composition root must hand it — the user repository's HTTP settings, read
 * as that repository's builder reads them — so one token goes to every Store
 * endpoint, and settings absent or not a section of keys refuse the boot
 * rather than send no credential. It requires no slot.
 */
import { type Module } from "@o3co/auth-provider-core";
export interface FoundationMfaFactorStoreModuleOptions {
    /**
     * The Store transport settings: the user repository's HTTP settings as the
     * configuration holds them (`repositories.user.http` in the standalone
     * template, which hands them here), whose `bearerToken`,
     * `timeout` and `maxResponseBytes` are the Store's, text read as numbers.
     * `{}` states none: no credential is sent, and the defaults apply.
     */
    readonly storeTransport: unknown;
}
/** The module, over the Store transport settings `options` hands it. */
export declare function foundationMfaFactorStoreModule(options: FoundationMfaFactorStoreModuleOptions): Module;
//# sourceMappingURL=module.d.mts.map