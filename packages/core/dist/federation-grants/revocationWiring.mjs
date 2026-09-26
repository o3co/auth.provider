/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
import { supportsSessionsOnlyRevocation, } from "../user-sessions/types.mjs";
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
export function requireFederationGrantSubjectRevocation(input) {
    const { module, subjectRevocation, federationGrantStore } = input;
    if (subjectRevocation === undefined) {
        throw new Error(`${module}: federationGrants.enabled = true requires a subjectRevocation component. ` +
            "A grant outlives the session it was agreed through, so the boundary is the only " +
            "thing that ends one a user has withdrawn from a replica that never saw the " +
            "withdrawal (D13). Install the bundled memory pair (single replica only) or an " +
            "adapter such as redisSessionStoresModule.");
    }
    if (!supportsSessionsOnlyRevocation(subjectRevocation)) {
        throw new Error(`${module}: the subjectRevocation adapter (kind "${subjectRevocation.kind}") does not carry ` +
            "the grants boundary. Federation grants need revokeSessionsBefore and " +
            "grantsRevokedBefore beside revokeBefore and revokedBefore (D13): without the " +
            "second boundary there is nothing to compare a grant against, and a subject-wide " +
            "revocation could not be asked to keep one. Update the adapter, or install one of " +
            "the bundled implementations.");
    }
    if (federationGrantStore !== undefined &&
        federationGrantStore.kind !== "memory" &&
        subjectRevocation.kind === "memory") {
        throw new Error(`${module}: grants are kept in "${federationGrantStore.kind}" while the subject ` +
            'boundary is kept in "memory". The grants outlive the process and the boundary ' +
            "does not, so a restart — or the replica that never held it — would hand out a " +
            "credential for a grant that was revoked. Wire the boundary into the same kind of " +
            "storage the grants are in (D13).");
    }
    return subjectRevocation;
}
