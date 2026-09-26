/**
 * What a deployment must have wired before a grant may outlive a session
 * (#593, D13).
 *
 * A federation grant is spendable offline, by a backend, with nobody watching.
 * The one thing that makes that safe is the subject boundary: a revocation
 * stamps it, and every retrieval compares against it. Two modules need the
 * same guarantees — the routes, which read the boundary on every call, and the
 * subject revocation service, which writes it — so the rules live here rather
 * than in either of them. A second copy would be the one that accepts an
 * adapter the other refuses.
 *
 * All three checks are structural: they are about what a component *is*, which
 * is knowable at boot. Whether a backend is reachable, and whether a
 * particular subject's record is well-formed, are not, and stay request-time
 * failures.
 */
import { type SubjectRevocation, type SupportsSessionsOnlyRevocation } from "../user-sessions/types.mjs";
import type { FederationGrantStore } from "./store.mjs";
/**
 * The subject revocation a grants deployment needs, or a refusal naming what
 * is missing.
 *
 * Deliberately not tolerant of an absence declared through
 * `SUBJECT_REVOCATION_ABSENCE_POLICY`. That policy lets a deployment say "this
 * capability is absent on purpose" and carry on; the sessions it covers still
 * end when their cookie does. A grant does not end when anything ends, so
 * "absent on purpose" is a decision to hand out offline credentials with no way
 * to take them back, and there is no configuration spelling for that.
 *
 * @param input.module the module doing the asking, for the message.
 * @param input.federationGrantStore what grants are kept in; `undefined` skips
 *   the durability pairing, for a caller that has its own refusal for a missing
 *   store and wants both messages rather than whichever came first.
 */
export declare function requireFederationGrantSubjectRevocation(input: {
    readonly module: string;
    readonly subjectRevocation: SubjectRevocation | undefined;
    readonly federationGrantStore?: FederationGrantStore | undefined;
}): SubjectRevocation & SupportsSessionsOnlyRevocation;
//# sourceMappingURL=revocationWiring.d.mts.map