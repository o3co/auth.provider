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
 * Subject-wide revocation with an operator's policy attached: the work of
 * `revokeAllForSubject` behind a component a module wires once, so the
 * caller names only a subject and, at most, what becomes of their
 * federation grants. See ADR 2026-09-17-federation-grants-offline-delegation.
 *
 * **Keeping is the reason it exists.** A password change wants sessions
 * gone; whether a backend's month-old calendar integration dies with it is
 * a question of residual access that differs per deployment. So the
 * allowance is configuration (`federationGrants.allowKeepOnSubjectRevocation`,
 * default `false`), not a call argument any caller could set. A `"keep"`
 * refused by policy is carried out as a full revocation, and the report
 * says so (see {@link SubjectRevocationReport.federationGrants}).
 */

import type { FederationGrantAuditEvent } from "../federation-grants/retrieve.mjs";
import {
	federationGrantCorrelationId,
	revokeFederationGrant,
} from "../federation-grants/revoke.mjs";
import type { FederationGrantStore } from "../federation-grants/store.mjs";
import { hasFederationGrantAuthorization } from "../federation-grants/types.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { loggableError } from "../logging/loggableError.mjs";
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
	/** Defaults to `"revoke"`. `"keep"` is a request, not an instruction: see the module note. */
	readonly federationGrants?: FederationGrantDisposition;
	/**
	 * While keeping, end the grants consented at or after this instant anyway:
	 * a compromise an operator can date, from which on the subject's consents
	 * may be somebody else's. Compared inclusively against `consent.at`, with
	 * no clock-skew widening (an operator's instant is not a guess). Ignored
	 * when the applied disposition is `"revoke"`.
	 */
	readonly revokeGrantsConsentedSince?: Date;
}

export interface SubjectRevocationReport extends RevokeAllForSubjectResult {
	/** Grants that were kept, and whose renewal in flight was ended. Empty when revoking. */
	readonly grantsRetired: readonly string[];
	/**
	 * Grants that were **kept**, and whose renewal could not be ended. Apart
	 * from `grantsFailed` ("revocation threw, safe to retry") because a Store
	 * that read them as one would retry by revoking grants the policy chose to
	 * keep: retrying one of these means asking for the retirement again.
	 */
	readonly grantsRetireFailed: readonly string[];
	/**
	 * What was asked for, what was done, and why when they differ.
	 *
	 * `complete: true` means the **applied** action completed, not that the
	 * requested one was honoured: a Store that asked to keep, was refused by
	 * policy, and reads only `complete` will believe grants survived that were
	 * all revoked. Read all three fields.
	 *
	 * `complete: false` is worse under `"keep"`. A full revocation stamps the
	 * grants boundary first, so a grant its pass missed is still refused at
	 * `/token`. `"keep"` advances no grants boundary, so a grant in
	 * `grantsFailed` (selected by `revokeGrantsConsentedSince`, left unwritten
	 * by an outage) stays usable until a retry succeeds.
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
	 * Optional, as for `revokeAllForSubject`, so the service installs in a
	 * deployment that declares either capability absent; an absence is
	 * reported in `unavailable` with `complete: false`. The module refuses a
	 * missing boundary while federation grants are enabled: a grant ends when
	 * nothing else does.
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
 * Wiring errors are refused here, once, rather than per request. With the
 * allowance on, an adapter that cannot stamp the two boundaries separately
 * would turn every `"keep"` into a full revocation, a failure that looks
 * like the policy working, so it is refused at construction.
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

			// One correlation ID per call, on either path: the service's own,
			// when it was composed with one, and otherwise this call's.
			const correlationId = federationGrantCorrelationId(deps.correlationId);
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
 * Sessions and tokens end; established grants stay. Same order as the full
 * revocation, for the same reason: the boundary is written before anything
 * is enumerated. Only the sessions boundary moves (`revokeSessionsBefore`),
 * so a grant covered by an earlier full revocation stays covered.
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
		deps.logger?.error({ err: loggableError(error), subject }, "revoke_all_watermark_failed");
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
			deps.logger?.error({ err: loggableError(error), subject }, "revoke_all_list_grants_failed");
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
				// The grant stays; its renewal does not: a reauthorization somebody
				// walked the subject into would widen the very grant this call
				// froze, and the pointer is the only part of it still reachable.
				// No handle: whichever intent is current is the one to end.
				const written = await store.retireIntent({ grantId: grant.id, now: new Date(now()) });
				// `ok: false` is a grant that had no renewal in flight. Nothing
				// to end is not a failure to end something.
				if (written.ok) grantsRetired.push(grant.id);
			} catch (error) {
				// Both count against `complete`: a renewal still current is not a
				// completed revocation. The list decides what a retry should do
				// (revoke again, or retire again), so they are two lists.
				(end ? grantsFailed : grantsRetireFailed).push(grant.id);
				failures.push({
					capability: "federationGrantStore",
					operation: end ? "revoke" : "retireIntent",
					grantId: grant.id,
					error,
				});
				deps.logger?.error(
					{ err: loggableError(error), subject, grantId: grant.id },
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
