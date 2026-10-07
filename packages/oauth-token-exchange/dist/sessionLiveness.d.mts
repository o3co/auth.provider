/**
 * The exchange's one reading of core's session lifecycle: whose live session a
 * `sid` names, so the grant's session rule reads no lifecycle answer itself.
 */
import type { SessionLifecycle } from "@o3co/auth-provider-core";
/**
 * The live session `sid` names, as its subject; `not_live` when it is not
 * live (a session closing or closed, or gone); `no_answer` for any other
 * answer, which the caller treats as an outage. A `liveness` that rejects is
 * not caught here.
 */
export declare function liveSessionSubject(lifecycle: Pick<SessionLifecycle, "liveness">, sid: string): Promise<{
    readonly subject: string;
} | "not_live" | "no_answer">;
//# sourceMappingURL=sessionLiveness.d.mts.map