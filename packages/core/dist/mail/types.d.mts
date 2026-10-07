/**
 * The `MailSender` port and its `mailSender` slot: how a one-time code the
 * provider issued leaves it (ADR 2026-09-25-multi-factor-authentication).
 * The provider hands a sender what a mail means and nothing rendered;
 * rendering (subject line, body, language), delivery and any limit on
 * sending are the sender's. In core so a sender's package and the MFA
 * package need not depend on each other. A leaf: it imports nothing.
 */
/** What a mail is for: a closed list, each a code the provider issued. */
export declare const MAIL_PURPOSES: readonly ["login_code", "account_email_proof", "email_factor_enrollment"];
/** One of {@link MAIL_PURPOSES}. */
export type MailPurpose = (typeof MAIL_PURPOSES)[number];
/** One mail the provider asks for: what it means, never how it reads. */
export interface MailSend {
    readonly purpose: MailPurpose;
    /** The account's subject (`User.id`), not a subject line. */
    readonly subject: string;
    /** The address on the account's user record at the time of the send; the provider keeps none. */
    readonly to: string;
    /** The code the mail carries: the one secret in it. */
    readonly code: string;
    /** When the provider stops accepting the code, in epoch milliseconds. */
    readonly expiresAtMs: number;
}
/**
 * What a send answers when the sender could decide it: `delivered`, the
 * relay holds the mail; `refused_at_limit`, a limit of the sender's or its
 * relay's refused it, and the provider answers `429`.
 */
export type MailSendResult = {
    readonly outcome: "delivered";
} | {
    readonly outcome: "refused_at_limit";
};
export interface MailSender {
    readonly kind: string;
    /**
     * Resolves with {@link MailSendResult}; rejects on anything else, an
     * outage the provider answers `503`, never "sent". The provider reads what
     * it resolved with through `mailSendOutcome`, so any other value is an
     * outage too. A rejection's loggable projection (`loggableError`) carries
     * nothing of the mail.
     */
    send(mail: MailSend): Promise<MailSendResult>;
}
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        /** Where the one-time codes the provider issues are sent. */
        readonly mailSender?: MailSender;
    }
}
//# sourceMappingURL=types.d.mts.map