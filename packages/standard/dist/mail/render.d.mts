/**
 * The standard mail text: for each purpose a subject line and a plain-text
 * body, in English, carrying the code and the minutes it has left. Nothing
 * else of the send is rendered: not the account, not the recipient, nothing
 * clickable. A send it cannot render is a `RangeError` that quotes nothing
 * of the send.
 */
import { type MailSend } from "@o3co/auth-provider-core";
/** A mail as the standard text renders it. */
export interface RenderedMail {
    /** The mail's subject line: one line, with no control character. */
    readonly subjectLine: string;
    readonly text: string;
}
/**
 * The subject line and body of `mail` at `nowMs`, the time the minutes left
 * are counted from.
 */
export declare function renderStandardMail(mail: MailSend, nowMs: number): RenderedMail;
//# sourceMappingURL=render.d.mts.map