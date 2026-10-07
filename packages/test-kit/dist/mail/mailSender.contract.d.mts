import { type MailSender } from "@o3co/auth-provider-core";
import type { ContractCase } from "../contractCase.mjs";
/** The ways a relay refuses a mail, each a case of the suite. `limit` is the one a sender answers rather than rejects. */
export declare const MAIL_RELAY_REFUSALS: readonly ["recipient_refused", "message_refused", "unreachable", "auth_failed", "temporary_failure", "limit"];
/** A way a relay refuses a mail: see {@link MAIL_RELAY_REFUSALS}. */
export type MailRelayRefusal = (typeof MAIL_RELAY_REFUSALS)[number];
/** A mail as the relay holds it: the recipients its envelope named, in order, and the whole message as text. */
export interface RelayedMail {
    readonly to: readonly string[];
    readonly content: string;
}
export interface MailSenderContractInput {
    /** A fresh sender over a relay that accepts, and what that relay holds, oldest first. */
    readonly build: () => {
        readonly sender: MailSender;
        readonly relayed: () => Promise<readonly RelayedMail[]>;
    };
    /**
     * A fresh sender over a relay that refuses as `refusal` names, answering
     * `reply` as its own text: the status line after `RCPT TO` or `DATA`, the
     * answer to `AUTH`, or the connection's failure for an unreachable one.
     */
    readonly refusing: (refusal: MailRelayRefusal, reply: string) => MailSender;
}
/** The cases of the `MailSender` contract over the senders `input` builds. */
export declare function mailSenderContract(input: MailSenderContractInput): readonly ContractCase[];
//# sourceMappingURL=mailSender.contract.d.mts.map