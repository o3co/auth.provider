/**
 * The oauth module's own section, `oauth {}`: the schema boot parses it with,
 * and the type the module's factories read it as (`deps.section`).
 *
 * Every object level is strict: a key it does not declare refuses boot, named
 * at its path, instead of being dropped unread. The defaults live in the
 * package's `config/reference.conf`, not here, and each leaf reads the string
 * an environment variable carries.
 *
 * Core declares none of these keys: its schema declares `core` alone, and the
 * section's defaults and variables are this package's alone. The module
 * refuses its removed keys (`oauth.refreshToken.legacyRtPolicy`,
 * `oauth.refreshToken.legacyTokenCompat`, `oauth.authorize.allowUnmarkedClients`,
 * `oauth.jwt.legacyTypAccept`)
 * before the schema parses, from its manifest's `relocatedFrom`, and so do the
 * modules other sections moved to for the paths they moved from
 * (`oauth.grants`, `oauth.dpop`, `oauth.jwt.signingKey`, …), while loaded.
 * Here a moved path may only be an empty object or null, which set nothing,
 * and a retired key — `oauth.jwt`'s flat key fields among them — is a key
 * this section does not declare.
 */
import { type AccessTokenConfig } from "@o3co/auth-provider-core";
import { z } from "zod";
export declare const oauthSectionSchema: z.ZodObject<{
    jwt: z.ZodObject<{
        issuer: z.ZodString;
        signingKey: z.ZodOptional<z.ZodNullable<z.ZodObject<{}, z.core.$strict>>>;
    }, z.core.$strict>;
    accessToken: z.ZodPipe<z.ZodObject<{
        defaultExpiresIn: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
        maxExpiresIn: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
    }, z.core.$strict>, z.ZodTransform<AccessTokenConfig, {
        defaultExpiresIn?: number | undefined;
        maxExpiresIn?: number | undefined;
    }>>;
    refreshToken: z.ZodObject<{
        expiresIn: z.ZodPreprocess<z.ZodNumber, unknown>;
    }, z.core.$strict>;
    oidcMode: z.ZodEnum<{
        "oidc-required": "oidc-required";
        dual: "dual";
    }>;
    requireEmailVerified: z.ZodOptional<z.ZodPreprocess<z.ZodBoolean, unknown>>;
    requireGrantTypeAllowlist: z.ZodOptional<z.ZodPreprocess<z.ZodBoolean, unknown>>;
    authorize: z.ZodOptional<z.ZodObject<{
        acrValues: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnion<readonly [z.ZodArray<z.ZodString>, z.ZodArray<z.ZodArray<z.ZodString>>]>>>;
    }, z.core.$strict>>;
    nonce: z.ZodOptional<z.ZodObject<{
        maxLength: z.ZodPreprocess<z.ZodNumber, unknown>;
    }, z.core.$strict>>;
    resourceIndicator: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodPreprocess<z.ZodBoolean, unknown>;
    }, z.core.$strict>>;
    consentPage: z.ZodOptional<z.ZodObject<{
        url: z.ZodString;
    }, z.core.$strict>>;
    clientIdMetadataDocuments: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodPreprocess<z.ZodBoolean, unknown>;
        allowedScopes: z.ZodOptional<z.ZodPipe<z.ZodUnion<readonly [z.ZodArray<z.ZodString>, z.ZodString]>, z.ZodTransform<string[], string | string[]>>>;
        allowedAudiences: z.ZodOptional<z.ZodPipe<z.ZodUnion<readonly [z.ZodArray<z.ZodString>, z.ZodString]>, z.ZodTransform<string[], string | string[]>>>;
        allowedHosts: z.ZodOptional<z.ZodPipe<z.ZodUnion<readonly [z.ZodArray<z.ZodString>, z.ZodString]>, z.ZodTransform<string[], string | string[]>>>;
        deniedHosts: z.ZodOptional<z.ZodPipe<z.ZodUnion<readonly [z.ZodArray<z.ZodString>, z.ZodString]>, z.ZodTransform<string[], string | string[]>>>;
        maxBytes: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
        timeoutMs: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
        cacheMaxAgeMs: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
        maxCacheEntries: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
        staleIfErrorMs: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
        negativeCacheMs: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
        maxConcurrentFetches: z.ZodOptional<z.ZodPreprocess<z.ZodNumber, unknown>>;
    }, z.core.$strict>>;
    grants: z.ZodOptional<z.ZodNullable<z.ZodObject<{}, z.core.$strict>>>;
    code: z.ZodOptional<z.ZodNullable<z.ZodObject<{}, z.core.$strict>>>;
    deviceAuthorization: z.ZodOptional<z.ZodNullable<z.ZodObject<{}, z.core.$strict>>>;
    tokenExchange: z.ZodOptional<z.ZodNullable<z.ZodObject<{}, z.core.$strict>>>;
    mtls: z.ZodOptional<z.ZodNullable<z.ZodObject<{}, z.core.$strict>>>;
    dpop: z.ZodOptional<z.ZodNullable<z.ZodObject<{}, z.core.$strict>>>;
    tokenBinding: z.ZodOptional<z.ZodNullable<z.ZodObject<{}, z.core.$strict>>>;
    revocation: z.ZodOptional<z.ZodObject<{
        accessToken: z.ZodEnum<{
            denylist: "denylist";
            unsupported: "unsupported";
        }>;
        subject: z.ZodOptional<z.ZodEnum<{
            unsupported: "unsupported";
            watermark: "watermark";
        }>>;
    }, z.core.$strict>>;
}, z.core.$strict>;
/** `oauth {}` as this module's schema parsed it: what `deps.section` holds. */
export type OAuthSection = z.output<typeof oauthSectionSchema>;
//# sourceMappingURL=section.d.mts.map