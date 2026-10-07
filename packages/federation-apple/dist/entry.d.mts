/**
 * The one reading of a `core.federations` entry of type `apple`: the keys it
 * carries beside the ones core owns (`enabled`, `type`, `trustUpstreamAmr`,
 * `callbackMeetsFreshness`, `callbackURL`), as a strict, flat schema. A key
 * written `null` reads as absent, and an absent key stays absent: what it means — no upstream logout
 * endpoint, no `redirect_to` accepted — is the provider's and the redirect
 * policy's reading, never a default filled in here. The provider's test seams
 * (`jwksUri`, `fetch`) are not entry keys: the type module's `fetch` option is
 * the seam.
 */
import { z } from "zod";
/**
 * The schema of an `apple` entry's own keys: strict (a key it does not name
 * refuses the entry), flat, and with exactly one client-secret source — a
 * static `clientSecret`, or `teamId`, `keyId` and `privateKey` (the `.p8`
 * PEM) to sign one, all three.
 */
export declare const appleEntrySchema: z.ZodPreprocess<z.ZodObject<{
    clientId: z.ZodString;
    clientSecret: z.ZodOptional<z.ZodString>;
    teamId: z.ZodOptional<z.ZodString>;
    keyId: z.ZodOptional<z.ZodString>;
    privateKey: z.ZodOptional<z.ZodString>;
    redirectAllowlist: z.ZodOptional<z.ZodArray<z.ZodString>>;
    sessionDomain: z.ZodOptional<z.ZodString>;
    authCallbackUrl: z.ZodOptional<z.ZodString>;
    clientUrl: z.ZodOptional<z.ZodString>;
    endSessionEndpoint: z.ZodOptional<z.ZodString>;
}, z.core.$strict>, unknown>;
/** An `apple` entry's own keys, as {@link appleEntrySchema} answers them. */
export type AppleEntry = z.output<typeof appleEntrySchema>;
//# sourceMappingURL=entry.d.mts.map