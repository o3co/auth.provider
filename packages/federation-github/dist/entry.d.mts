/**
 * The one reading of a `core.federations` entry of type `github`: the keys it
 * carries beside the ones core owns (`enabled`, `type`, `trustUpstreamAmr`,
 * `callbackMeetsFreshness`, `callbackURL`), as a strict, flat schema. A key
 * written `null` reads as absent, and an absent key stays absent: what it means — GitHub's own logout,
 * no `redirect_to` accepted — is the provider's and the redirect policy's
 * reading, never a default filled in here.
 */
import { z } from "zod";
/**
 * The schema of a `github` entry's own keys: strict (a key it does not name
 * refuses the entry) and flat. A refusal names the key, never its value.
 */
export declare const githubEntrySchema: z.ZodPreprocess<z.ZodObject<{
    clientId: z.ZodString;
    clientSecret: z.ZodString;
    redirectAllowlist: z.ZodOptional<z.ZodArray<z.ZodString>>;
    sessionDomain: z.ZodOptional<z.ZodString>;
    authCallbackUrl: z.ZodOptional<z.ZodString>;
    clientUrl: z.ZodOptional<z.ZodString>;
    endSessionEndpoint: z.ZodOptional<z.ZodString>;
}, z.core.$strict>, unknown>;
/** A `github` entry's own keys, as {@link githubEntrySchema} answers them. */
export type GithubEntry = z.output<typeof githubEntrySchema>;
//# sourceMappingURL=entry.d.mts.map