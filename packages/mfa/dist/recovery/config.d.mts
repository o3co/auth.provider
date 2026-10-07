import { z } from "zod";
/** The recovery-code factor's section, as its module parses it before any factory runs. */
export declare const mfaRecoveryCodeFactorConfigSchema: z.ZodObject<{
    enabled: z.ZodPreprocess<z.ZodBoolean, unknown>;
    count: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
}, z.core.$strict>;
/** `mfa-recovery-code-factor` as its schema reads it. */
export type MfaRecoveryCodeFactorSettings = z.infer<typeof mfaRecoveryCodeFactorConfigSchema>;
//# sourceMappingURL=config.d.mts.map