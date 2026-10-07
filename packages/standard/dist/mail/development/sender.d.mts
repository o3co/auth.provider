/**
 * The development `MailSender`: it delivers nothing and writes one line at
 * info per send, `mail_code_issued`, carrying the purpose and the code and
 * nothing else of the mail, so a developer reads the code off the log. A
 * code in a log line is a secret wherever the log is read by more than the
 * developer, so its module refuses every deployment that is not one.
 */
import type { Logger, MailSender } from "@o3co/auth-provider-core";
export interface StandardDevelopmentMailSenderOptions {
    /** Where each code is written. */
    readonly logger: Logger;
}
/** The development sender: every send logged, and answered delivered. */
export declare function createStandardDevelopmentMailSender(options: StandardDevelopmentMailSenderOptions): MailSender;
//# sourceMappingURL=sender.d.mts.map