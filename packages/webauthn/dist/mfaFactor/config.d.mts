import { z } from "zod";
/** The WebAuthn second factor's section, as its module parses it before any factory runs. */
export declare const webauthnMfaFactorConfigSchema: z.ZodObject<{
    enabled: z.ZodPreprocess<z.ZodBoolean, unknown>;
    userVerification: z.ZodEnum<{
        required: "required";
        preferred: "preferred";
        discouraged: "discouraged";
    }>;
}, z.core.$strict>;
/** `webauthn-mfa-factor` as its schema reads it. */
export type WebAuthnMfaFactorSettings = z.infer<typeof webauthnMfaFactorConfigSchema>;
//# sourceMappingURL=config.d.mts.map