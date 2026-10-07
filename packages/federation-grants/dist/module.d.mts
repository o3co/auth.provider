import { z } from "zod";
/**
 * The slice both routes read — core's own declaration of it, projected.
 *
 * Not a restatement. `AppConfigSchema` is a strip-mode object and the boot
 * planner composes every module's `configSchema` into one parse, so a key this
 * module does not declare is GONE by the time the factory reads it: a narrower
 * copy here would leave the connections and every retrieval limit at their
 * defaults while an operator's file said otherwise, and the boot refusals that
 * exist to catch a bad one would never see it. That is how this was found.
 *
 * Taking core's shape rather than mirroring it also keeps the `${?VAR}`
 * coercions (#288) in one place: HOCON substitutes every environment override
 * as a string, and `enabled` is the one where a leftover string reads as off.
 */
export declare const federationGrantsConfigSchema: z.ZodObject<{
    federationGrants: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodOptional<z.ZodPreprocess<z.ZodBoolean, unknown>>;
        defaultExpiresIn: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
        maxExpiresIn: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
        refreshBuffer: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
        ineligibleRetryAfter: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
        refreshFailureBackoff: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
        upstreamTimeoutMs: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
        upstreamHardTimeoutMs: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
        refreshLockTtlMs: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
        lockWaitMs: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
        persistRetryBudgetMs: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
        tombstoneRetention: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
        allowKeepOnSubjectRevocation: z.ZodOptional<z.ZodPreprocess<z.ZodBoolean, unknown>>;
        identityLookup: z.ZodOptional<z.ZodEnum<{
            unsupported: "unsupported";
            required: "required";
        }>>;
        consent: z.ZodOptional<z.ZodObject<{
            url: z.ZodOptional<z.ZodString>;
        }, z.core.$strip>>;
        encryptionMode: z.ZodOptional<z.ZodEnum<{
            required: "required";
            "allow-plaintext": "allow-plaintext";
        }>>;
        encryptionKeys: z.ZodOptional<z.ZodArray<z.ZodObject<{
            id: z.ZodString;
            key: z.ZodString;
        }, z.core.$strip>>>;
        connections: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodObject<{
            federation: z.ZodString;
            scopes: z.ZodArray<z.ZodString>;
            resource: z.ZodOptional<z.ZodString>;
            boundary: z.ZodString;
            maxAccessTokenLifetime: z.ZodPreprocess<z.ZodNumber, unknown>;
            allowScopeSubsets: z.ZodOptional<z.ZodPreprocess<z.ZodBoolean, unknown>>;
            authorizationParams: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
            callbackURL: z.ZodOptional<z.ZodString>;
            identityClaims: z.ZodOptional<z.ZodArray<z.ZodString>>;
        }, z.core.$strip>>>;
    }, z.core.$strip>>;
}, z.core.$strip>;
export declare const federationGrantBackgroundModule: import("@o3co/auth-provider-core").Module;
export declare const federationGrantsModule: import("@o3co/auth-provider-core").Module;
/**
 * The documented installation form: `modules: [...federationGrantsModules]`.
 * The registry first, though the planner would sort them anyway — reading it
 * in dependency order is how the pair explains itself at a composition root.
 */
export declare const federationGrantsModules: readonly [import("@o3co/auth-provider-core").Module, import("@o3co/auth-provider-core").Module];
//# sourceMappingURL=module.d.mts.map