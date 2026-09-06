import type { Module } from "@o3co/auth-provider-core";
import { z } from "zod";
import type { DidDocumentResolver } from "./resolver/types.mjs";
import type { VerifierRegistry } from "./verifiers/registry.mjs";
export declare const didConfigSchema: z.ZodObject<{
    did: z.ZodDefault<z.ZodObject<{
        enabled: z.ZodDefault<z.ZodBoolean>;
        algorithm: z.ZodOptional<z.ZodString>;
        supportedAlgorithms: z.ZodDefault<z.ZodArray<z.ZodString>>;
        messageMaxAgeSec: z.ZodDefault<z.ZodCoercedNumber<unknown>>;
        allowedAudiences: z.ZodDefault<z.ZodArray<z.ZodString>>;
    }, z.core.$strip>>;
}, z.core.$strip>;
export type DidModuleOptions = {
    resolver: DidDocumentResolver;
    verifierRegistry?: VerifierRegistry;
} | {
    resolverFactory: (config: Record<string, unknown>) => DidDocumentResolver;
    verifierRegistry?: VerifierRegistry;
};
/**
 * Module that registers the DID grant handler.
 *
 * Accepts either a pre-built resolver or a factory that receives the DID grant
 * config section and returns a resolver.
 *
 * Register with createApp's modules array.
 */
export declare const oauthDidModule: (options: DidModuleOptions) => Module;
//# sourceMappingURL=module.d.mts.map