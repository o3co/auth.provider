import { z } from "zod";
/** The email factor's section, as its module parses it before any factory runs. */
export declare const mfaEmailFactorConfigSchema: z.ZodObject<{
    enabled: z.ZodPreprocess<z.ZodBoolean, unknown>;
    addsMfa: z.ZodPreprocess<z.ZodBoolean, unknown>;
    codeTtlSeconds: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
}, z.core.$strict>;
/** `mfa-email-factor` as its schema reads it. */
export type MfaEmailFactorSettings = z.infer<typeof mfaEmailFactorConfigSchema>;
//# sourceMappingURL=config.d.mts.map