/**
 * The one reading of what a `MailSender` answered. Only a plain record whose
 * one own data property is `outcome`, holding `delivered` or
 * `refused_at_limit`, is that answer; anything else — no answer, another
 * outcome, more than the outcome, an accessor, a value that cannot be read —
 * is an outage, never "sent".
 */
/** What a send came to, as the provider acts on it: `429` for a limit, `503` for an outage. */
export type MailSendOutcome = "delivered" | "refused_at_limit" | "outage";
/** `answer`, what a sender's `send` resolved with, as {@link MailSendOutcome}. */
export declare function mailSendOutcome(answer: unknown): MailSendOutcome;
//# sourceMappingURL=outcome.d.mts.map