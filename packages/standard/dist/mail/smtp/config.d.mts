import { z } from "zod";
/** The ways a connection to the relay is secured. */
export declare const STANDARD_SMTP_SECURE_MODES: readonly ["starttls", "tls", "none"];
/** The SMTP mail sender's section, as its module parses it before any factory runs. */
export declare const standardSmtpMailSenderConfigSchema: z.ZodObject<{
    host: z.ZodOptional<z.ZodString>;
    port: z.ZodUnion<readonly [z.ZodNumber, z.ZodPipe<z.ZodPipe<z.ZodString, z.ZodTransform<number, string>>, z.ZodNumber>]>;
    secure: z.ZodEnum<{
        starttls: "starttls";
        tls: "tls";
        none: "none";
    }>;
    user: z.ZodOptional<z.ZodString>;
    password: z.ZodOptional<z.ZodString>;
    from: z.ZodOptional<z.ZodString>;
}, z.core.$strict>;
/** `standard-smtp-mail-sender` as its schema reads it. */
export type StandardSmtpMailSenderSettings = z.infer<typeof standardSmtpMailSenderConfigSchema>;
//# sourceMappingURL=config.d.mts.map