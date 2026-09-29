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
 * Grant revocation and listing as library calls for a Store (an operator
 * console, a user's "connected applications" page), not routes: this
 * provider mounts no admin route and has no operator identity model, so
 * authenticating the person and checking ownership belong to the Store. A
 * Store must:
 *
 *  - list by the **authenticated** local subject, never one from the request;
 *  - check that a selected grant belongs to that subject before withdrawing;
 *  - use `by: "subject"` for a user's own withdrawal and `"operator"` for an
 *    administrative one — they are different facts.
 *
 * The listing carries no credential but does carry internal metadata
 * (revisions, versions, consent instants, failure stamps); a Store projects
 * what its page needs.
 */

import { randomUUID } from "node:crypto";
import { federationGrantAuditMetadata } from "./auditMetadata.mjs";
import type { FederationGrantAuditEvent } from "./retrieve.mjs";
import type { FederationGrantStore, FederationGrantWrite } from "./store.mjs";
import type { FederationGrant, FederationGrantRevokedBy } from "./types.mjs";

/**
 * The correlation ID an operation's events carry: the caller's, when it is
 * not empty, else a generated one (an empty string correlates nothing).
 * Called once per operation, so everything it audits shares the one ID.
 */
export function federationGrantCorrelationId(given: string | undefined): string {
	return typeof given === "string" && given.length > 0 ? given : randomUUID();
}

export interface FederationGrantAdministrationDeps {
	readonly store: FederationGrantStore;
	/** Sampled at the write, never once per batch. */
	now(): Date;
	/**
	 * Told what was ended, after it was ended. A sink that throws changes
	 * nothing: the record is already revoked, and reporting otherwise would be
	 * worse than not reporting at all.
	 */
	audit?(event: FederationGrantAuditEvent): void | Promise<void>;
	/**
	 * What correlates this call's events with the caller's own record of it —
	 * a request ID, a job ID. Absent, the events get one of their own:
	 * a correlation ID that is empty correlates nothing, and an operator
	 * reading the sink still has to tell one pass from another.
	 */
	readonly correlationId?: string;
}

/**
 * End one grant, with the store's atomic, always-winning write. It **does not
 * read the record first**: a record whose credential cannot be decoded must
 * still be endable.
 *
 * `{ ok: false }` means the write changed nothing (already revoked, or
 * absent), not a failure; an outage rejects.
 */
export async function revokeFederationGrant(
	deps: FederationGrantAdministrationDeps,
	grantId: string,
	by: FederationGrantRevokedBy,
): Promise<FederationGrantWrite> {
	const written = await deps.store.revoke(grantId, by, deps.now());
	if (written.ok) await tell(deps, written.grant, by);
	return written;
}

/**
 * Every record this subject has, unordered, `pending` and retained terminal
 * ones included (a user should see a grant in progress and one they lost).
 * An outage rejects rather than answering `[]`, which a user would act on.
 */
export async function listFederationGrantsForSubject(
	deps: FederationGrantAdministrationDeps,
	subject: string,
): Promise<readonly FederationGrant[]> {
	return deps.store.listBySubject(subject, deps.now());
}

/** Built from the record that was ended, never from what the caller claimed. */
async function tell(
	deps: FederationGrantAdministrationDeps,
	grant: FederationGrant,
	by: FederationGrantRevokedBy,
): Promise<void> {
	const sink = deps.audit;
	if (sink === undefined) return;
	try {
		await sink({
			type: "federation.grant.revoked",
			correlationId: federationGrantCorrelationId(deps.correlationId),
			grantId: grant.id,
			clientId: grant.clientId,
			subject: grant.subject,
			...federationGrantAuditMetadata(grant),
			outcome: by,
		});
	} catch {
		// The revocation happened. A sink that failed is an operator's problem
		// with their sink, and turning it into a failed revocation would send
		// them to undo something that was right.
	}
}
