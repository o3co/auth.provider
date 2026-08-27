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

import type { Logger } from "../logging/Logger.mjs";
import type { SubjectRevocation, SubjectSessionIndex } from "./types.mjs";

/**
 * Per-session teardown, supplied by the caller.
 *
 * `@o3co/auth-provider-oauth` owns `cascadeLogout`, which performs the
 * carefully ordered four-step store cascade for one session. Core cannot
 * import it without inverting the package dependency, so the caller passes it
 * in and this helper stays responsible only for *which* sessions and *in what
 * order relative to the watermark*.
 */
export type CascadeSession = (sid: string) => Promise<{ readonly ok: boolean }>;

export interface RevokeAllForSubjectOptions {
	readonly subject: string;
	/** How long the watermark must outlive — normally the access-token TTL. */
	readonly watermarkTtlMs: number;
	readonly cascadeSession: CascadeSession;
	readonly subjectSessionIndex?: SubjectSessionIndex;
	readonly subjectRevocation?: SubjectRevocation;
	readonly logger?: Logger;
	/** Injectable for tests; defaults to `Date.now`. */
	readonly now?: () => number;
}

export interface RevokeAllForSubjectResult {
	/** Session ids whose cascade completed. */
	readonly sessionsRevoked: readonly string[];
	/** Session ids whose cascade failed — still live, safe to retry. */
	readonly sessionsFailed: readonly string[];
	/** Whether the access-token watermark was written. */
	readonly tokensRevoked: boolean;
	/**
	 * Capabilities that were not wired, and therefore not exercised.
	 *
	 * Load-bearing rather than informational: the caller invokes this
	 * immediately after writing a new credential, and a bare success while
	 * nothing was revoked is the worst outcome this helper could produce. A
	 * non-empty list means the revocation was **partial** and the caller must
	 * treat it as a failure.
	 */
	readonly unavailable: readonly ("subjectSessionIndex" | "subjectRevocation")[];
}

/**
 * Invalidate everything this authorization server issued for one subject
 * (#296).
 *
 * The Store owns the credential-change flow — issuing the reset token,
 * delivering it, writing the new password. What it cannot do from outside is
 * kill the sessions and tokens already minted against the old credential, and
 * that is this function's whole job. The service calls it immediately after
 * the credential write.
 *
 * **The watermark is written first, before any session is cascaded.** Two
 * reasons, and both are the difference between working and not:
 *
 *   - A refresh rotation or a concurrent login on another replica can mint a
 *     token *during* the cascade loop. Enumerating sessions first and writing
 *     the watermark afterwards leaves that token outside both mechanisms —
 *     its session was not in the list, and its `iat` predates the watermark
 *     that had not yet been written.
 *   - On partial failure the safe direction is "tokens dead, some sessions
 *     perhaps alive", not the reverse. A live session with no usable token
 *     can be cleaned up on retry; a live token is the thing being revoked.
 *
 * Does **not** fix #276 — the local logout route still does not run the
 * cascade for its own session. This builds on `cascadeLogout`, which is
 * complete; the gap there is that one caller does not invoke it.
 */
export async function revokeAllForSubject(
	opts: RevokeAllForSubjectOptions,
): Promise<RevokeAllForSubjectResult> {
	const now = opts.now ?? Date.now;
	const unavailable: ("subjectSessionIndex" | "subjectRevocation")[] = [];

	// Step 1 — watermark, before anything else. See the ordering note above.
	let tokensRevoked = false;
	if (opts.subjectRevocation === undefined) {
		unavailable.push("subjectRevocation");
	} else {
		const at = now();
		await opts.subjectRevocation.revokeBefore(
			opts.subject,
			new Date(at),
			new Date(at + opts.watermarkTtlMs),
		);
		tokensRevoked = true;
	}

	// Step 2 — cascade every session the subject holds.
	const sessionsRevoked: string[] = [];
	const sessionsFailed: string[] = [];
	if (opts.subjectSessionIndex === undefined) {
		unavailable.push("subjectSessionIndex");
	} else {
		const sids = await opts.subjectSessionIndex.listSids(opts.subject);
		for (const sid of sids) {
			// Sequential, not concurrent: each cascade is itself a multi-store
			// sequence whose ordering matters, and a credential change is rare
			// enough that fanning out to save milliseconds is not worth the
			// extra load it would put on the same stores mid-incident.
			let ok: boolean;
			try {
				ok = (await opts.cascadeSession(sid)).ok;
			} catch (err) {
				opts.logger?.error({ err, subject: opts.subject, sid }, "revoke_all_cascade_failed");
				ok = false;
			}
			if (ok) {
				sessionsRevoked.push(sid);
				await opts.subjectSessionIndex.removeSid(opts.subject, sid);
			} else {
				// Left in the index deliberately: the entry is what a retry
				// enumerates. Removing it would strand a live session.
				sessionsFailed.push(sid);
			}
		}
	}

	if (unavailable.length > 0) {
		opts.logger?.error({ subject: opts.subject, unavailable }, "revoke_all_for_subject_incomplete");
	}

	return { sessionsRevoked, sessionsFailed, tokensRevoked, unavailable };
}
