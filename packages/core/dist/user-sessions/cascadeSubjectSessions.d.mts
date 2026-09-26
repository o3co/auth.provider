/**
 * Every session one subject holds, torn down one at a time (#296, #593).
 *
 * It is its own function because two callers now need exactly this loop and
 * its bookkeeping: `revokeAllForSubject`, and the subject revocation service's
 * `"keep"` path, which stamps a different boundary first and then cascades the
 * same sessions. A second copy would be the one that forgets why a failed
 * cascade leaves its index entry alone.
 */
import type { Logger } from "../logging/Logger.mjs";
import type { CascadeSession, RevokeAllForSubjectFailure } from "./revokeAllForSubject.mjs";
import type { SubjectSessionIndex } from "./types.mjs";
export interface SubjectSessionCascade {
    /** Session ids whose cascade completed. */
    readonly revoked: readonly string[];
    /** Session ids whose cascade failed — still live, and still in the index. */
    readonly failed: readonly string[];
    /** Store calls that were attempted and threw. */
    readonly failures: readonly RevokeAllForSubjectFailure[];
}
/**
 * **Never throws.** Its callers have already written something they cannot
 * undo, and a partial result they can act on is worth more than an exception.
 */
export declare function cascadeSubjectSessions(input: {
    readonly subject: string;
    readonly index: SubjectSessionIndex;
    readonly cascadeSession: CascadeSession;
    readonly logger?: Logger;
}): Promise<SubjectSessionCascade>;
//# sourceMappingURL=cascadeSubjectSessions.d.mts.map