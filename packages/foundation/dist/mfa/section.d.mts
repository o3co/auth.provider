import { z } from "zod";
/** The section's name: the module's. */
export declare const FOUNDATION_MFA_FACTOR_STORE_SECTION = "foundation-mfa-factor-store";
/** The section: the four URLs, each optional here, and no other key. */
declare const schema: z.ZodObject<{
    listUrl: z.ZodOptional<z.ZodString>;
    createUrl: z.ZodOptional<z.ZodString>;
    updateUrl: z.ZodOptional<z.ZodString>;
    deleteUrl: z.ZodOptional<z.ZodString>;
}, z.core.$strict>;
/** The section as the module declares it: its schema, and the package's reference. */
export declare const foundationMfaFactorStoreSection: {
    readonly schema: z.ZodObject<{
        listUrl: z.ZodOptional<z.ZodString>;
        createUrl: z.ZodOptional<z.ZodString>;
        updateUrl: z.ZodOptional<z.ZodString>;
        deleteUrl: z.ZodOptional<z.ZodString>;
    }, z.core.$strict>;
    readonly reference: import("node:url").URL;
};
/**
 * The lifecycle of a module that reads the section: its store is built at
 * boot whether or not anything requires it, so the reader always runs.
 */
export declare const foundationMfaFactorStoreLifecycle: {
    readonly mfaFactorStore: {
        readonly eager: true;
    };
};
/** The section as its schema reads it. */
export type FoundationMfaFactorStoreSection = z.output<typeof schema>;
/** The Store's four MFA factor endpoints. */
export interface FoundationMfaFactorStoreUrls {
    readonly listUrl: string;
    readonly createUrl: string;
    readonly updateUrl: string;
    readonly deleteUrl: string;
}
/**
 * The four URLs of a parsed section, or a `RangeError` naming each one
 * missing by its path and its variable.
 */
export declare function readFoundationMfaFactorStoreUrls(section: FoundationMfaFactorStoreSection): FoundationMfaFactorStoreUrls;
export {};
//# sourceMappingURL=section.d.mts.map