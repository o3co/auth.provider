/**
 * The one reading of a `core.federations` entry of type `oidc`: the keys it
 * carries beside the ones core owns (`enabled`, `type`, `trustUpstreamAmr`,
 * `callbackMeetsFreshness`, `callbackURL`), as a strict, flat schema. A key written `null` reads as
 * absent, and an absent key stays absent: what it means — the default scopes,
 * discovery on, UserInfo when the issuer publishes it — is the provider's
 * reading (`oidc.mts`), never a default filled in here.
 */
import { z } from "zod";
/**
 * The schema of an `oidc` entry's own keys: strict (a key it does not name
 * refuses the entry), flat, and with exactly one of `clientSecret`
 * (`client_secret_basic`) and `privateKey` (`private_key_jwt`).
 */
export declare const oidcEntrySchema: z.ZodPreprocess<z.ZodObject<{
    issuer: z.ZodString;
    clientId: z.ZodString;
    clientSecret: z.ZodOptional<z.ZodString>;
    privateKey: z.ZodOptional<z.ZodPipe<z.ZodUnknown, z.ZodTransform<string | {
        pem: string;
        kid?: string | undefined;
        alg?: string | undefined;
    }, unknown>>>;
    scopes: z.ZodOptional<z.ZodArray<z.ZodString>>;
    discovery: z.ZodOptional<z.ZodPreprocess<z.ZodBoolean, unknown>>;
    endpoints: z.ZodOptional<z.ZodObject<{
        authorizationEndpoint: z.ZodOptional<z.ZodString>;
        tokenEndpoint: z.ZodOptional<z.ZodString>;
        jwksUri: z.ZodOptional<z.ZodString>;
        userinfoEndpoint: z.ZodOptional<z.ZodString>;
        endSessionEndpoint: z.ZodOptional<z.ZodString>;
    }, z.core.$strict>>;
    idTokenSignedResponseAlg: z.ZodOptional<z.ZodString>;
    userInfo: z.ZodOptional<z.ZodPreprocess<z.ZodBoolean, unknown>>;
    clockToleranceSeconds: z.ZodOptional<z.ZodNumber>;
    redirectAllowlist: z.ZodOptional<z.ZodArray<z.ZodString>>;
    sessionDomain: z.ZodOptional<z.ZodString>;
    authCallbackUrl: z.ZodOptional<z.ZodString>;
    clientUrl: z.ZodOptional<z.ZodString>;
}, z.core.$strict>, unknown>;
/** An `oidc` entry's own keys, as {@link oidcEntrySchema} answers them. */
export type OidcEntry = z.output<typeof oidcEntrySchema>;
//# sourceMappingURL=entry.d.mts.map