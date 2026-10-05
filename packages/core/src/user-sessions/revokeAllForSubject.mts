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

import type { FederationGrantAuditEvent } from "../federation-grants/retrieve.mjs";
import {
	federationGrantCorrelationId,
	listFederationGrantsForSubject,
	revokeFederationGrant,
} from "../federation-grants/revoke.mjs";
import type { FederationGrantStore } from "../federation-grants/store.mjs";
import type { FederationGrant } from "../federation-grants/types.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { loggableError } from "../logging/loggableError.mjs";
import { cascadeSubjectSessions, type SubjectSessionCascade } from "./cascadeSubjectSessions.mjs";
import { stampSubjectBoundary } from "./stampSubjectBoundary.mjs";
import type { SubjectRevocation, SubjectSessionIndex } from "./types.mjs";

/**
 * Per-session teardown, supplied by the caller: `cascadeLogout`, the ordered
 * store cascade for one session, lives in `@o3co/auth-provider-oauth`, which
 * core cannot import without inverting the package dependency. This helper
 * decides only which sessions, and in what order relative to the watermark.
 */
export type CascadeSession = (sid: string) => Promise<{ readonly ok: boolean }>;

/**
 * The optional slots this helper consumes, named so a caller can branch on
 * them. `federationGrantStore` appears only for the failures it can report:
 * leaving it out is a decision, not an omission, so it is never listed in
 * `unavailable`.
 */
export type RevokeAllForSubjectCapability =
	| "subjectSessionIndex"
	| "subjectRevocation"
	| "federationGrantStore";

/**
 * One store call that was attempted and threw. Distinct from
 * {@link RevokeAllForSubjectResult.unavailable}: that is a composition gap
 * fixed by wiring a module, this a backend outage fixed by retrying, and
 * collapsing them would send an operator to the wrong runbook.
 */
export interface RevokeAllForSubjectFailure {
	readonly capability: RevokeAllForSubjectCapability;
	readonly operation:
		| "revokeBefore"
		| "listSids"
		| "removeSid"
		| "listBySubject"
		| "revoke"
		/** The subject revocation service's two: a sessions-only stamp, and a renewal it could not end. */
		| "revokeSessionsBefore"
		| "retireIntent";
	/** The session the failing call concerned, for the per-session operations. */
	readonly sid?: string;
	/** The grant the failing call concerned, for the per-grant operations. */
	readonly grantId?: string;
	/**
	 * Which of a boundary's two writes threw (`revokeBefore`,
	 * `revokeSessionsBefore`): `1`, the first; `2`, the one made after it
	 * took effect, when a boundary may be in force without covering what was
	 * minted while the first was in flight. Run the revocation again.
	 */
	readonly stamp?: 1 | 2;
	readonly error: unknown;
}

export interface RevokeAllForSubjectOptions {
	readonly subject: string;
	/**
	 * How long the watermark must outlive. Size it with
	 * `resolveSubjectRevocationHorizonMs`, which reads the session, the
	 * refresh token and the access-token **maximum** — a watermark that
	 * expires before any of them takes the backstop with it, and nothing in
	 * the configuration says which of the three is longest. See the TTL
	 * contract on {@link SubjectRevocation}.
	 */
	readonly watermarkTtlMs: number;
	readonly cascadeSession: CascadeSession;
	readonly subjectSessionIndex?: SubjectSessionIndex;
	readonly subjectRevocation?: SubjectRevocation;
	/**
	 * Supplying it asks for the subject's federation grants to be ended too.
	 * **Omitting it is not a missing capability**: see
	 * {@link RevokeAllForSubjectResult.grantsRequested}.
	 */
	readonly federationGrantStore?: FederationGrantStore;
	/**
	 * Told about each grant this call ended, on the same terms as every other
	 * revocation: one event per write that changed something, built from the
	 * record rather than from what was asked for, and a sink that throws
	 * changes nothing.
	 */
	readonly federationGrantAudit?: (event: FederationGrantAuditEvent) => void | Promise<void>;
	/** Carried into the grant audit events when the caller has one. */
	readonly correlationId?: string;
	readonly logger?: Logger;
	/** Injectable for tests; defaults to `Date.now`. */
	readonly now?: () => number;
}

export interface RevokeAllForSubjectResult {
	/** Session ids whose cascade completed. */
	readonly sessionsRevoked: readonly string[];
	/** Session ids whose cascade failed — still live, safe to retry. */
	readonly sessionsFailed: readonly string[];
	/**
	 * Whether the access-token watermark was written. It is written twice, the
	 * second time once the first has settled; true when either write took
	 * effect. A write that threw is in `failures` with its `stamp`, and
	 * `complete` is then `false`.
	 */
	readonly tokensRevoked: boolean;
	/**
	 * Whether a grant store was supplied, and the grant pass therefore ran.
	 * `false` is not a gap: a deployment with no grants is not incomplete for
	 * revoking none. A caller that expects grants ended checks this field;
	 * meanwhile the watermark's boundary, which the adapters apply to grants
	 * too, covers the omission.
	 */
	readonly grantsRequested: boolean;
	/** Grant ids this call ended. A grant that was already over is not one. */
	readonly grantsRevoked: readonly string[];
	/** Grant ids whose write threw — still live, safe to retry. */
	readonly grantsFailed: readonly string[];
	/**
	 * Capabilities that were not wired, and therefore not exercised. A
	 * non-empty list means the revocation was **partial** and the caller must
	 * treat it as a failure: this runs right after a new credential is
	 * written, and a bare success while nothing was revoked is the worst
	 * outcome it could produce.
	 */
	readonly unavailable: readonly RevokeAllForSubjectCapability[];
	/**
	 * Store calls that were wired, attempted, and threw. Empty on the happy
	 * path. See {@link RevokeAllForSubjectFailure} for why this is separate
	 * from `unavailable`.
	 */
	readonly failures: readonly RevokeAllForSubjectFailure[];
	/**
	 * Everything that was asked for actually happened: the one field a caller
	 * has to check. Computed here once, since a four-way condition each
	 * integrator derives on its own reads as success when gotten wrong.
	 */
	readonly complete: boolean;
}

/**
 * Invalidates everything this authorization server issued for one subject.
 * The Store owns the credential-change flow (reset token, delivery, new
 * password); this kills the sessions and tokens already minted against the
 * old credential, and is called right after the credential write.
 *
 * **The watermark is written first**, before any session is cascaded:
 *
 *   - A refresh rotation or a login on another replica can mint a token
 *     during the cascade. Enumerating sessions first would leave that token
 *     outside both mechanisms: its session was not listed, and its `iat`
 *     predates a watermark not yet written.
 *   - On partial failure the safe direction is "tokens dead, some sessions
 *     perhaps alive": a live session with no usable token can be cleaned up
 *     on retry; a live token is the thing being revoked.
 *
 * It is stamped again once that write has taken effect
 * (`stampSubjectBoundary`), so it also covers a token minted while the write
 * was in flight.
 *
 * **This never throws** once it has checked its arguments (a `RangeError`
 * for a `watermarkTtlMs` that is not a positive whole number of
 * milliseconds, before anything is written). The caller has already written the new credential
 * and has no undo, so an exception would replace a partial result it could
 * act on (retry these sids, alert on that outage) with nothing. Every store
 * failure is reported, and `complete` is the one field to check.
 *
 * Federation grants are ended last, and only when a store is supplied, so a
 * grant store's outage cannot cost the watermark and session passes. An
 * outage in any pass still leaves the other two done.
 */
export async function revokeAllForSubject(
	opts: RevokeAllForSubjectOptions,
): Promise<RevokeAllForSubjectResult> {
	if (!(Number.isSafeInteger(opts.watermarkTtlMs) && opts.watermarkTtlMs > 0)) {
		throw new RangeError(
			`revokeAllForSubject: watermarkTtlMs must be a positive whole number of milliseconds, and was ${String(opts.watermarkTtlMs)}`,
		);
	}
	const now = opts.now ?? Date.now;
	const unavailable: RevokeAllForSubjectCapability[] = [];
	const failures: RevokeAllForSubjectFailure[] = [];

	// Step 1 — watermark, before anything else. See the ordering note above.
	let tokensRevoked = false;
	if (opts.subjectRevocation === undefined) {
		unavailable.push("subjectRevocation");
	} else {
		const revocation = opts.subjectRevocation;
		const stamped = await stampSubjectBoundary(
			(before, expiresAt) => revocation.revokeBefore(opts.subject, before, expiresAt),
			now,
			opts.watermarkTtlMs,
		);
		tokensRevoked = stamped.written;
		if (stamped.failure !== undefined) {
			const { error, stamp } = stamped.failure;
			// Reported, not thrown, and the cascade below still runs: a watermark
			// that could not be written does not make the subject's sessions any
			// less worth killing, and returning here would revoke nothing at all.
			failures.push({ capability: "subjectRevocation", operation: "revokeBefore", stamp, error });
			opts.logger?.error(
				{ err: loggableError(error), subject: opts.subject, stamp },
				"revoke_all_watermark_failed",
			);
		}
	}

	// Step 2 — cascade every session the subject holds.
	let sessions: SubjectSessionCascade = { revoked: [], failed: [], failures: [] };
	if (opts.subjectSessionIndex === undefined) {
		unavailable.push("subjectSessionIndex");
	} else {
		sessions = await cascadeSubjectSessions({
			subject: opts.subject,
			index: opts.subjectSessionIndex,
			cascadeSession: opts.cascadeSession,
			logger: opts.logger,
		});
		failures.push(...sessions.failures);
	}

	// Step 3 — end every federation grant the subject has. Last: an outage
	// here must not cost the two passes above.
	const grantsRevoked: string[] = [];
	const grantsFailed: string[] = [];
	const grantStore = opts.federationGrantStore;
	if (grantStore !== undefined) {
		const deps = {
			store: grantStore,
			now: () => new Date(now()),
			audit: opts.federationGrantAudit,
			// One ID for the pass, so that its events read as one operation; the
			// caller's own when it has one.
			correlationId: federationGrantCorrelationId(opts.correlationId),
		};
		let grants: readonly FederationGrant[] = [];
		try {
			// Pending and retained terminal records included, on purpose. A
			// pending one is an authorization the subject is in the middle of
			// giving, and leaving it to complete after its owner revoked
			// everything is exactly the hole this pass exists to close.
			grants = await listFederationGrantsForSubject(deps, opts.subject);
		} catch (error) {
			// Not the same as "this subject has no grants", which is why it is
			// reported: a listing outage that read as an empty subject would
			// return a clean, complete result having revoked nothing.
			failures.push({ capability: "federationGrantStore", operation: "listBySubject", error });
			opts.logger?.error(
				{ err: loggableError(error), subject: opts.subject },
				"revoke_all_list_grants_failed",
			);
		}
		for (const grant of grants) {
			try {
				const written = await revokeFederationGrant(deps, grant.id, "subject");
				// A write that changed nothing means the grant was already over
				// — somebody else revoked it, or it expired — so it is neither
				// revoked here nor a failure. Only a throw is an outage.
				if (written.ok) grantsRevoked.push(grant.id);
			} catch (error) {
				// The loop continues. The remaining grants are independent
				// records, and stopping at the first outage would leave the
				// ones after it live for no reason.
				grantsFailed.push(grant.id);
				failures.push({
					capability: "federationGrantStore",
					operation: "revoke",
					grantId: grant.id,
					error,
				});
				opts.logger?.error(
					{ err: loggableError(error), subject: opts.subject, grantId: grant.id },
					"revoke_all_revoke_grant_failed",
				);
			}
		}
	}

	if (unavailable.length > 0) {
		opts.logger?.error({ subject: opts.subject, unavailable }, "revoke_all_for_subject_incomplete");
	}

	// `grantsFailed` is not a term of its own: every entry in it was pushed
	// alongside the failure that produced it, which `failures` already carries.
	// `sessionsFailed` is a term because a cascade that answers `{ ok: false }`
	// reports no failure at all.
	const complete =
		unavailable.length === 0 && failures.length === 0 && sessions.failed.length === 0;

	return {
		sessionsRevoked: sessions.revoked,
		sessionsFailed: sessions.failed,
		tokensRevoked,
		grantsRequested: grantStore !== undefined,
		grantsRevoked,
		grantsFailed,
		unavailable,
		failures,
		complete,
	};
}
