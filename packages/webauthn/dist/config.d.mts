import { z } from "zod";
export declare const webauthnConfigSchema: z.ZodObject<{
    rpId: z.ZodString;
    rpName: z.ZodString;
    origin: z.ZodArray<z.ZodString>;
    challengeTtlMs: z.ZodNumber;
    attestationPreference: z.ZodEnum<{
        none: "none";
        indirect: "indirect";
        direct: "direct";
        enterprise: "enterprise";
    }>;
    userVerification: z.ZodEnum<{
        required: "required";
        preferred: "preferred";
        discouraged: "discouraged";
    }>;
}, z.core.$strip>;
export type WebAuthnConfig = z.infer<typeof webauthnConfigSchema>;
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        readonly webauthnConfig?: WebAuthnConfig;
    }
}
//# sourceMappingURL=config.d.mts.map