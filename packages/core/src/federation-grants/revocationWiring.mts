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
 * What a deployment must have wired before a grant may outlive a session.
 *
 * A grant is spent offline by a backend; what makes that safe is the subject
 * boundary, which a revocation stamps and every retrieval checks. The routes
 * (readers) and the subject revocation service (writer) share these rules
 * from here so neither accepts an adapter the other refuses.
 *
 * The checks are structural and run at boot; reachability and per-subject
 * record validity stay request-time failures.
 */

import {
	type SubjectRevocation,
	type SupportsSessionsOnlyRevocation,
	supportsSessionsOnlyRevocation,
} from "../user-sessions/types.mjs";
import type { FederationGrantStore } from "./store.mjs";

/**
 * The subject revocation a grants deployment needs, or a refusal naming what
 * is missing.
 *
 * Deliberately ignores an absence declared through
 * `SUBJECT_REVOCATION_ABSENCE_POLICY`: sessions still end with their cookie,
 * but a grant would then be an offline credential nothing can take back.
 *
 * @param input.module the module doing the asking, for the message.
 * @param input.federationGrantStore what grants are kept in; `undefined` skips
 *   the durability pairing check (for a caller that reports a missing store
 *   itself).
 */
export function requireFederationGrantSubjectRevocation(input: {
	readonly module: string;
	readonly subjectRevocation: SubjectRevocation | undefined;
	readonly federationGrantStore?: FederationGrantStore | undefined;
}): SubjectRevocation & SupportsSessionsOnlyRevocation {
	const { module, subjectRevocation, federationGrantStore } = input;
	if (subjectRevocation === undefined) {
		throw new Error(
			`${module}: federationGrants.enabled = true requires a subjectRevocation component. ` +
				"A grant outlives the session it was agreed through, so the boundary is the only " +
				"thing that ends one a user has withdrawn from a replica that never saw the " +
				"withdrawal (D13). Install the bundled memory pair (single replica only) or an " +
				"adapter such as redisSessionStoresModule.",
		);
	}
	if (!supportsSessionsOnlyRevocation(subjectRevocation)) {
		throw new Error(
			`${module}: the subjectRevocation adapter (kind "${subjectRevocation.kind}") does not carry ` +
				"the grants boundary. Federation grants need revokeSessionsBefore and " +
				"grantsRevokedBefore beside revokeBefore and revokedBefore (D13): without the " +
				"second boundary there is nothing to compare a grant against, and a subject-wide " +
				"revocation could not be asked to keep one. Update the adapter, or install one of " +
				"the bundled implementations.",
		);
	}
	if (
		federationGrantStore !== undefined &&
		federationGrantStore.kind !== "memory" &&
		subjectRevocation.kind === "memory"
	) {
		throw new Error(
			`${module}: grants are kept in "${federationGrantStore.kind}" while the subject ` +
				'boundary is kept in "memory". The grants outlive the process and the boundary ' +
				"does not, so a restart — or the replica that never held it — would hand out a " +
				"credential for a grant that was revoked. Wire the boundary into the same kind of " +
				"storage the grants are in (D13).",
		);
	}
	return subjectRevocation;
}
