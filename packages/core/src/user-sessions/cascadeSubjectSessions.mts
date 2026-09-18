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
export async function cascadeSubjectSessions(input: {
	readonly subject: string;
	readonly index: SubjectSessionIndex;
	readonly cascadeSession: CascadeSession;
	readonly logger?: Logger;
}): Promise<SubjectSessionCascade> {
	const { subject, index, cascadeSession, logger } = input;
	const revoked: string[] = [];
	const failed: string[] = [];
	const failures: RevokeAllForSubjectFailure[] = [];

	let sids: readonly string[] = [];
	try {
		sids = await index.listSids(subject);
	} catch (error) {
		// Nothing to enumerate means nothing to cascade, but the boundary the
		// caller stamped first may already be in force — which is why this is a
		// reported partial result rather than a thrown one.
		failures.push({ capability: "subjectSessionIndex", operation: "listSids", error });
		logger?.error({ err: error, subject }, "revoke_all_list_sids_failed");
	}

	for (const sid of sids) {
		// Sequential, not concurrent: each cascade is itself a multi-store
		// sequence whose ordering matters, and a credential change is rare
		// enough that fanning out to save milliseconds is not worth the extra
		// load it would put on the same stores mid-incident.
		let ok: boolean;
		try {
			ok = (await cascadeSession(sid)).ok;
		} catch (err) {
			logger?.error({ err, subject, sid }, "revoke_all_cascade_failed");
			ok = false;
		}
		if (!ok) {
			// Left in the index deliberately: the entry is what a retry
			// enumerates. Removing it would strand a live session.
			failed.push(sid);
			continue;
		}
		revoked.push(sid);
		try {
			await index.removeSid(subject, sid);
		} catch (error) {
			// Bookkeeping only, and deliberately not fatal to the loop: the
			// session's cascade already succeeded, so it stays counted as
			// revoked. A stale entry costs the next call one redundant cascade,
			// which is idempotent — whereas aborting here would leave the
			// subject's remaining sessions live.
			failures.push({ capability: "subjectSessionIndex", operation: "removeSid", sid, error });
			logger?.error({ err: error, subject, sid }, "revoke_all_remove_sid_failed");
		}
	}

	return { revoked, failed, failures };
}
