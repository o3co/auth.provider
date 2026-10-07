import type { CsrfGuard } from "../../browser-session/types.mjs";
import type { LoginCompletion } from "../../session-admission/login-completion.mjs";
import type { Establishment, InterruptAdmission } from "../../session-admission/requirement.mjs";
/** A `LoginCompletion` for tests, that records what it was handed and can stand in for a session store that is down. */
export interface RecordingLoginCompletion extends LoginCompletion {
    /** Every establishment core built that `establishSession` was handed, oldest first. */
    readonly establishments: readonly Establishment[];
    /** Every interruption core answered that `answerInterruption` was handed, oldest first. */
    readonly interruptions: readonly InterruptAdmission[];
    /** The session records it holds: one per login established, none for one rolled back. */
    readonly records: number;
    /** From now on, `establishSession` answers the session store's outage at `create` and writes nothing. */
    failSessionStore(error: unknown): void;
    /** Answer again. */
    recover(): void;
}
export interface RecordingLoginCompletionOptions {
    /** The deployment's CSRF guard: `answerInterruption` issues the `403`'s fresh token through it. */
    readonly csrfGuard?: CsrfGuard;
    /**
     * `false` for a completion over no session store — the session package's
     * composition without a `UserSessionStore`: no record is written and no
     * `sid` answered. A session record per login by default.
     */
    readonly sessionRecords?: boolean;
}
/**
 * A `LoginCompletion` that keeps the contract over the express session it
 * is handed: `establishSession` counts a session record, regenerates the
 * session, writes the signed-in state and saves it, answering a made-up
 * `sid` — a failure after the record is counted rolls it back;
 * `answerInterruption` regenerates, opens the ceremony on the new id,
 * saves and answers the requirement's `403`, with a fresh token from
 * `options.csrfGuard` when it is given one; `renewSession` regenerates,
 * writes back the signed-in fields the session held and a fresh renewal
 * nonce, and saves.
 */
export declare function createRecordingLoginCompletion(options?: RecordingLoginCompletionOptions): RecordingLoginCompletion;
//# sourceMappingURL=loginCompletion.d.mts.map