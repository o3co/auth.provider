/**
 * The one reading of a `core.federations` entry of type `google`: the keys it
 * carries beside the ones core owns (`enabled`, `type`, `trustUpstreamAmr`,
 * `callbackMeetsFreshness`, `callbackURL`), as a strict, flat schema. A key
 * written `null` reads as absent, and an absent key stays absent: what it means — offline access,
 * the RFC 9207 `iss` required, no `redirect_to` accepted — is the provider's
 * and the redirect policy's reading, never a default filled in here.
 */
import { z } from "zod";
/**
 * The schema of a `google` entry's own keys: strict (a key it does not name
 * refuses the entry) and flat.
 */
export declare const googleEntrySchema: z.ZodPreprocess<z.ZodObject<{
    clientId: z.ZodString;
    clientSecret: z.ZodString;
    redirectAllowlist: z.ZodOptional<z.ZodArray<z.ZodString>>;
    sessionDomain: z.ZodOptional<z.ZodString>;
    authCallbackUrl: z.ZodOptional<z.ZodString>;
    clientUrl: z.ZodOptional<z.ZodString>;
    endSessionEndpoint: z.ZodOptional<z.ZodString>;
    requireAuthorizationResponseIss: z.ZodOptional<z.ZodPreprocess<z.ZodBoolean, unknown>>;
    accessType: z.ZodOptional<z.ZodEnum<{
        offline: "offline";
        online: "online";
    }>>;
}, z.core.$strict>, unknown>;
/** A `google` entry's own keys, as {@link googleEntrySchema} answers them. */
export type GoogleEntry = z.output<typeof googleEntrySchema>;
//# sourceMappingURL=entry.d.mts.map