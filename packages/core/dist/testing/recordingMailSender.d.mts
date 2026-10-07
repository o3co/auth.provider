/**
 * A `MailSender` for tests: it keeps every send it delivers instead of
 * delivering it, and can stand in for a sender at a limit or a relay that is
 * down. Each instruction holds until the next.
 */
import type { MailSend, MailSender } from "../mail/types.mjs";
export interface RecordingMailSender extends MailSender {
    readonly kind: "recording";
    /** Every send it delivered, oldest first, as frozen copies. */
    readonly sent: readonly MailSend[];
    /** From now on, every send answers `refused_at_limit` and keeps nothing. */
    refuseAtLimit(): void;
    /** From now on, every send rejects with `error` and keeps nothing — a relay that is down. */
    failWith(error: unknown): void;
    /** Deliver again. */
    recover(): void;
}
export declare function createRecordingMailSender(): RecordingMailSender;
//# sourceMappingURL=recordingMailSender.d.mts.map