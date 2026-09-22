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
 * Subject-wide revocation with an operator's policy attached (#593, D13).
 *
 * `revokeAllForSubject` is a function a Store calls with every store it has
 * and a TTL it has to size correctly. This is the same work behind a component
 * a module wires once: the caller names a subject and, at most, what should
 * happen to their federation grants.
 *
 * **Keeping is the reason it exists.** A subject-wide revocation exists for
 * two very different events. A user changing their password wants their
 * sessions gone; whether the calendar integration a backend has been using for
 * a month should die with it is a question about residual access, and the
 * answer differs per deployment. So the allowance is configuration
 * (`federationGrants.allowKeepOnSubjectRevocation`, default `false`) rather
 * than an argument: a flag on the call would let any caller decide it, which
 * is not what an operator policy is.
 *
 * What the caller asks for and what happened are both reported, because they
 * can differ: a `"keep"` refused by policy is carried out as a full
 * revocation. See {@link SubjectRevocationReport.complete} for the sentence
 * that matters operationally.
 */

import { randomUUID } from "node:crypto";
import type { FederationGrantAuditEvent } from "../federation-grants/retrieve.mjs";
import { revokeFederationGrant } from "../federation-grants/revoke.mjs";
import type { FederationGrantStore } from "../federation-grants/store.mjs";
import { hasFederationGrantAuthorization } from "../federation-grants/types.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { cascadeSubjectSessions, type SubjectSessionCascade } from "./cascadeSubjectSessions.mjs";
import {
	type CascadeSession,
	type RevokeAllForSubjectCapability,
	type RevokeAllForSubjectFailure,
	type RevokeAllForSubjectResult,
	revokeAllForSubject,
} from "./revokeAllForSubject.mjs";
import {
	type SubjectRevocation,
	type SubjectSessionIndex,
	type SupportsSessionsOnlyRevocation,
	supportsSessionsOnlyRevocation,
} from "./types.mjs";

/** What should become of the subject's federation grants. */
export type FederationGrantDisposition = "revoke" | "keep";

export interface SubjectRevocationRequest {
	readonly subject: string;
	/** Defaults to `"revoke"`. `"keep"` is a request, not an instruction — see the module note. */
	readonly federationGrants?: FederationGrantDisposition;
	/**
	 * While keeping, end the grants consented at or after this instant anyway.
	 *
	 * What it is for: a compromise an operator can date. Everything the subject
	 * agreed to from that moment on may have been agreed to by somebody else,
	 * and is ended; what they agreed to before it is what "keep" keeps. The
	 * comparison is against `consent.at`, is inclusive, and is not widened by
	 * any clock skew — an operator's instant is not a guess.
	 *
	 * Ignored when the applied disposition is `"revoke"`: everything is already
	 * being ended.
	 */
	readonly revokeGrantsConsentedSince?: Date;
}

export interface SubjectRevocationReport extends RevokeAllForSubjectResult {
	/**
	 * Grants that were kept, and whose renewal in flight was ended (D13).
	 *
	 * Empty on the revoking path, where there is nothing to keep a renewal for.
	 */
	readonly grantsRetired: readonly string[];
	/**
	 * Grants that were **kept**, and whose renewal could not be ended.
	 *
	 * Separate from `grantsFailed`, and the separation is the point: that
	 * field means "the revocation write threw — still live, safe to retry",
	 * and a Store that read these two as one would retry by revoking grants
	 * the operator's policy had just chosen to keep. Retrying one of these
	 * means asking for the retirement again, not for a revocation.
	 */
	readonly grantsRetireFailed: readonly string[];
	/**
	 * What was asked for, what was done, and — when they differ — why.
	 *
	 * `complete: true` means the **applied** action completed. It does not mean
	 * the requested one was honoured: a Store that asked to keep, was refused
	 * by policy, and reads only `complete` will believe the subject's grants
	 * survived when every one of them was revoked. Read all three fields.
	 *
	 * And `complete: false` is worse under `"keep"` than under `"revoke"`. A
	 * full revocation stamps the grants boundary before it enumerates
	 * anything, so a grant its pass could not reach is refused at `/token` and
	 * revoked durably there; the retry only tidies up. `"keep"` advances no
	 * grants boundary — that is the mode — so a grant in `grantsFailed`,
	 * selected by `revokeGrantsConsentedSince` and left unwritten by an
	 * outage, stays usable until the retry succeeds. Nothing else will end it.
	 */
	readonly federationGrants: {
		readonly requested: FederationGrantDisposition;
		readonly applied: FederationGrantDisposition;
		readonly reason?: "keep_not_allowed";
	};
}

export interface SubjectRevocationService {
	revokeAllForSubject(request: SubjectRevocationRequest): Promise<SubjectRevocationReport>;
}

export interface SubjectRevocationServiceDeps {
	/**
	 * Optional for the reason the free function's are: #406 lets a deployment
	 * declare either capability absent, and a service that could not be
	 * *installed* in such a deployment would be a harder demand than the
	 * operation it wraps. An absence is reported exactly as
	 * `revokeAllForSubject` reports it — in `unavailable`, with
	 * `complete: false` — rather than refused here. What IS refused is a
	 * missing boundary while federation grants are enabled, which the module
	 * checks: a grant ends when nothing else does.
	 */
	readonly subjectSessionIndex?: SubjectSessionIndex;
	readonly subjectRevocation?: SubjectRevocation;
	readonly cascadeSession: CascadeSession;
	/**
	 * How long a boundary must outlive, from
	 * `resolveSubjectRevocationHorizonMs`. Required rather than defaulted: the
	 * number depends on configuration this module cannot see, and a guess makes
	 * the backstop expire before what it is the backstop for.
	 */
	readonly watermarkTtlMs: number;
	readonly federationGrantStore?: FederationGrantStore;
	/** `federationGrants.allowKeepOnSubjectRevocation`, already resolved. */
	readonly allowKeep: boolean;
	readonly federationGrantAudit?: (event: FederationGrantAuditEvent) => void | Promise<void>;
	readonly correlationId?: string;
	readonly logger?: Logger;
	/** Injectable for tests; defaults to `Date.now`. */
	readonly now?: () => number;
}

/**
 * Wiring errors are refused here, once, rather than answered per request.
 *
 * An operator who turned the allowance on and got a full revocation on every
 * call would read the outcome as the policy working — `"keep"` is precisely
 * the mode whose failure looks like success from the outside. So an adapter
 * that cannot stamp the two boundaries separately is a refusal at
 * construction, where a composition error belongs.
 */
export function createSubjectRevocationService(
	deps: SubjectRevocationServiceDeps,
): SubjectRevocationService {
	if (!Number.isFinite(deps.watermarkTtlMs) || deps.watermarkTtlMs <= 0) {
		throw new RangeError(
			`the subject revocation service needs a positive watermark TTL in milliseconds, and was given ${String(deps.watermarkTtlMs)}. ` +
				"Size it with resolveSubjectRevocationHorizonMs: a boundary that expires before the credentials it covers is not a backstop.",
		);
	}
	const revocation = deps.subjectRevocation;
	if (deps.allowKeep && (revocation === undefined || !supportsSessionsOnlyRevocation(revocation))) {
		throw new TypeError(
			`federationGrants.allowKeepOnSubjectRevocation is on, but the subjectRevocation adapter (kind "${revocation?.kind ?? "absent"}") ` +
				"cannot stamp a sessions-only boundary: keeping a subject's federation grants needs revokeSessionsBefore and " +
				"grantsRevokedBefore. Without them every keep would silently revoke, which reads like the policy working.",
		);
	}
	const now = deps.now ?? Date.now;

	return {
		async revokeAllForSubject(request) {
			const since = request.revokeGrantsConsentedSince;
			if (since !== undefined && Number.isNaN(since.getTime())) {
				// Before the first write, deliberately: a subject revocation
				// that stamped the boundary and then refused the argument would
				// have done the irreversible half of a call the caller was told
				// did not happen.
				throw new RangeError("revokeGrantsConsentedSince must be a valid Date");
			}
			const requested: FederationGrantDisposition = request.federationGrants ?? "revoke";
			const applied: FederationGrantDisposition =
				requested === "keep" && deps.allowKeep ? "keep" : "revoke";
			const federationGrants: SubjectRevocationReport["federationGrants"] =
				requested === applied
					? { requested, applied }
					: { requested, applied, reason: "keep_not_allowed" };

			// One correlation ID per call, on either path (#618): the service's
			// own, when it was composed with one, and otherwise this call's.
			const correlationId = deps.correlationId ?? randomUUID();
			if (applied === "revoke") {
				const result = await revokeAllForSubject({
					subject: request.subject,
					watermarkTtlMs: deps.watermarkTtlMs,
					cascadeSession: deps.cascadeSession,
					subjectSessionIndex: deps.subjectSessionIndex,
					subjectRevocation: revocation,
					federationGrantStore: deps.federationGrantStore,
					federationGrantAudit: deps.federationGrantAudit,
					correlationId,
					logger: deps.logger,
					now,
				});
				return { ...result, grantsRetired: [], grantsRetireFailed: [], federationGrants };
			}
			// Narrowed by the construction refusal above: `allowKeep` is what
			// admits this path, and it is refused without a capable adapter.
			return {
				...(await keep(
					deps,
					revocation as SubjectRevocation & SupportsSessionsOnlyRevocation,
					now,
					request.subject,
					since,
					correlationId,
				)),
				federationGrants,
			};
		},
	};
}

/**
 * Sessions and tokens end; established grants stay.
 *
 * The order is the one the full revocation makes, and for the same reason: the
 * boundary is written before anything is enumerated, so a session or a token
 * minted while this runs is covered by something. What differs is only which
 * boundary — `revokeSessionsBefore` moves the sessions one and leaves the
 * grants one exactly where it was. That is what makes "keep" a decision rather
 * than a race: a grant covered by an earlier full revocation stays covered,
 * because this never moves that boundary backwards.
 */
async function keep(
	deps: SubjectRevocationServiceDeps,
	revocation: SubjectRevocation & SupportsSessionsOnlyRevocation,
	now: () => number,
	subject: string,
	since: Date | undefined,
	correlationId: string,
): Promise<Omit<SubjectRevocationReport, "federationGrants">> {
	const failures: RevokeAllForSubjectFailure[] = [];
	const unavailable: RevokeAllForSubjectCapability[] = [];
	const at = now();
	let tokensRevoked = false;
	try {
		await revocation.revokeSessionsBefore(
			subject,
			new Date(at),
			new Date(at + deps.watermarkTtlMs),
		);
		tokensRevoked = true;
	} catch (error) {
		failures.push({
			capability: "subjectRevocation",
			operation: "revokeSessionsBefore",
			error,
		});
		deps.logger?.error({ err: error, subject }, "revoke_all_watermark_failed");
	}

	let sessions: SubjectSessionCascade = { revoked: [], failed: [], failures: [] };
	if (deps.subjectSessionIndex === undefined) {
		unavailable.push("subjectSessionIndex");
	} else {
		sessions = await cascadeSubjectSessions({
			subject,
			index: deps.subjectSessionIndex,
			cascadeSession: deps.cascadeSession,
			logger: deps.logger,
		});
		failures.push(...sessions.failures);
	}

	const grantsRevoked: string[] = [];
	const grantsFailed: string[] = [];
	const grantsRetired: string[] = [];
	const grantsRetireFailed: string[] = [];
	const store = deps.federationGrantStore;
	if (store !== undefined) {
		const grantDeps = {
			store,
			now: () => new Date(now()),
			audit: deps.federationGrantAudit,
			correlationId,
		};
		let grants: Awaited<ReturnType<FederationGrantStore["listBySubject"]>> = [];
		try {
			grants = await store.listBySubject(subject, new Date(now()));
		} catch (error) {
			failures.push({ capability: "federationGrantStore", operation: "listBySubject", error });
			deps.logger?.error({ err: error, subject }, "revoke_all_list_grants_failed");
		}
		for (const grant of grants) {
			if (grant.status === "revoked") continue;
			// A grant with no authorization is a consent in flight, and keeping
			// what the subject established is not keeping what they had not
			// finished agreeing to. One the operator dated as compromised goes
			// the same way.
			const end =
				!hasFederationGrantAuthorization(grant) ||
				(since !== undefined && grant.consent.at.getTime() >= since.getTime());
			try {
				if (end) {
					const written = await revokeFederationGrant(grantDeps, grant.id, "subject");
					if (written.ok) grantsRevoked.push(grant.id);
					continue;
				}
				// The grant stays. Its renewal does not: a reauthorization
				// somebody walked the subject into would widen the very grant
				// this call froze, and by now the pointer is the only part of
				// it this provider can still reach (D13). No handle — whichever
				// intent is current is the one to end.
				const written = await store.retireIntent({ grantId: grant.id, now: new Date(now()) });
				// `ok: false` is a grant that had no renewal in flight. Nothing
				// to end is not a failure to end something.
				if (written.ok) grantsRetired.push(grant.id);
			} catch (error) {
				// Counted against `complete`, both of them: reporting a
				// completed revocation while a renewal somebody else started is
				// still current would be the wrong half of the truth. Which
				// list they land in decides what a retry should DO — revoke
				// again, or retire again — so they are not one list.
				(end ? grantsFailed : grantsRetireFailed).push(grant.id);
				failures.push({
					capability: "federationGrantStore",
					operation: end ? "revoke" : "retireIntent",
					grantId: grant.id,
					error,
				});
				deps.logger?.error(
					{ err: error, subject, grantId: grant.id },
					end ? "revoke_all_revoke_grant_failed" : "revoke_all_retire_intent_failed",
				);
			}
		}
	}

	return {
		sessionsRevoked: sessions.revoked,
		sessionsFailed: sessions.failed,
		tokensRevoked,
		grantsRequested: store !== undefined,
		grantsRevoked,
		grantsFailed,
		grantsRetired,
		grantsRetireFailed,
		unavailable,
		failures,
		complete: unavailable.length === 0 && failures.length === 0 && sessions.failed.length === 0,
	};
}

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge
// ---------------------------------------------------------------------------

/**
 * Optional, and installed by a module of its own (`@o3co/auth-provider-oauth`),
 * because building it needs the whole session cascade. A deployment that only
 * serves grants has no use for it, and a route bundle that suddenly required
 * every session store would break the deployments that have none.
 */
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly subjectRevocationService?: SubjectRevocationService;
	}
}
