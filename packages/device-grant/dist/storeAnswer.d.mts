/** A wrapper `readPollOutcome` or `readDecisionOutcome` refuses. */
export type StoreAnswerRefusal = {
    readonly ok: false;
    readonly refused: "outcome_not_an_object";
} | {
    readonly ok: false;
    readonly refused: "outcome_malformed";
    readonly field: "status" | "intervalSeconds" | "current";
};
/** A `poll` answer as read: an approval's record is handed on unread. */
export type PollAnswer = {
    readonly status: "not_found" | "expired" | "denied" | "pending";
} | {
    readonly status: "slow_down";
    readonly intervalSeconds: number;
} | {
    readonly status: "approved";
    readonly authorization: unknown;
};
/** An `approve` or `deny` answer as read: an applied decision's record is handed on unread. */
export type DecisionAnswer = {
    readonly status: "ok";
    readonly authorization: unknown;
} | {
    readonly status: "not_found" | "expired";
} | {
    readonly status: "already_decided";
    readonly current: "approved" | "denied";
};
/**
 * A `poll` answer read once. A `slow_down` interval is held to the rule
 * `readDeviceAuthorization` holds a record's interval to: a finite number of
 * seconds, zero or more.
 */
export declare function readPollOutcome(outcome: unknown): {
    readonly ok: true;
    readonly answer: PollAnswer;
} | StoreAnswerRefusal;
/**
 * An `approve` or `deny` answer read once. An `already_decided` holds a
 * decision: `approved` or `denied`, never `pending`.
 */
export declare function readDecisionOutcome(outcome: unknown): {
    readonly ok: true;
    readonly answer: DecisionAnswer;
} | StoreAnswerRefusal;
//# sourceMappingURL=storeAnswer.d.mts.map