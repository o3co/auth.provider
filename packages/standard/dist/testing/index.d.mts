/**
 * `@o3co/auth-provider-standard/testing`: the builders a test assembles this
 * package's configuration with, so no test writes a section of this
 * package's by hand. Each is a configuration fragment at its section's name,
 * with the reference defaults and the keys a test lays over them. Test code
 * imports it; production code never does.
 */
import type { STANDARD_SMTP_SECURE_MODES } from "../mail/smtp/config.mjs";
/** What {@link standardSmtpMailSenderConfigForTests} lays over the reference defaults. */
export interface StandardSmtpMailSenderConfigForTestsOptions {
    readonly host?: string;
    readonly port?: number;
    readonly secure?: (typeof STANDARD_SMTP_SECURE_MODES)[number];
    readonly user?: string;
    readonly password?: string;
    readonly from?: string;
}
/** The SMTP mail sender's section, `standard-smtp-mail-sender`, as the package's reference.conf resolves it, with `options` laid over it. */
export declare function standardSmtpMailSenderConfigForTests(options?: StandardSmtpMailSenderConfigForTestsOptions): {
    "standard-smtp-mail-sender": {
        host?: string;
        port: number;
        secure: (typeof STANDARD_SMTP_SECURE_MODES)[number];
        user?: string;
        password?: string;
        from?: string;
    };
};
//# sourceMappingURL=index.d.mts.map