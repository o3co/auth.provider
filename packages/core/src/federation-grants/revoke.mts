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
 * The two calls a Store makes, rather than two routes this server mounts
 * (#593, D13).
 *
 * `revokeFederationGrant` is how an operator's console ends a grant.
 * `listFederationGrantsForSubject` is what lets a Store offer a user a
 * "connected applications" page — and without it a user has no direct way to
 * withdraw a grant at all, which is why it is part of the same decision.
 *
 * They are library calls because this provider mounts no admin route and has
 * no operator identity model to authorize one with. Authenticating the person,
 * and checking that the grant they picked is theirs, belongs to the Store,
 * which has both. What a Store owes its callers:
 *
 *  - list by the **authenticated** local subject, never by one submitted with
 *    the request;
 *  - check that a grant the user selected belongs to that subject before
 *    withdrawing it;
 *  - use `by: "subject"` for a user's own withdrawal and `"operator"` for an
 *    administrative one — they are different facts, and the runbook tells an
 *    operator different things about each.
 *
 * What comes back from the listing carries no credential, but it does carry
 * this provider's internal domain metadata: revisions, versions, consent
 * instants, failure stamps. It is a library result and not a page. A Store
 * projects the fields its page needs.
 */

import type { FederationGrantAuditEvent } from "./retrieve.mjs";
import type { FederationGrantStore, FederationGrantWrite } from "./store.mjs";
import {
	type FederationGrant,
	type FederationGrantRevokedBy,
	hasFederationGrantAuthorization,
} from "./types.mjs";

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
	/** Carried into the audit event when the caller has one to correlate by. */
	readonly correlationId?: string;
}

/**
 * End one grant.
 *
 * It calls the store's own atomic, always-winning write and **does not read
 * the record first**. A read in front of this would refuse exactly the cleanup
 * an operator needs most: the Redis store deliberately allows revoking a
 * record whose credential cannot be decoded, and a record nobody can decode is
 * one that must still be endable.
 *
 * `{ ok: false }` is not a failure. It means the write changed nothing —
 * because the grant is already revoked, or is not there — and a Store retrying
 * after a timeout must be able to tell that from an outage. An outage rejects.
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
 * Every record this subject has, in no particular order — `pending` ones and
 * retained terminal ones included.
 *
 * A page that listed only active grants would hide the authorization a user is
 * in the middle of giving, and the one they are wondering why they lost.
 *
 * An outage rejects rather than answering `[]`. "You have no connected
 * applications" is a sentence a user acts on.
 */
export async function listFederationGrantsForSubject(
	deps: FederationGrantAdministrationDeps,
	subject: string,
): Promise<readonly FederationGrant[]> {
	return deps.store.listBySubject(subject, deps.now());
}

/**
 * What an event can say about the grant it ended (D18).
 *
 * D18 carries the caller, the owner, the upstream subject, the connection, the
 * resource and the scopes **where they have been established** — and for a
 * revocation they are, because the record the write returned is the
 * establishment. Leaving them out made the revocation events the only ones in
 * the family that did not say *what access ended*: an operator reading
 * `federation.grant.revoked` got a grant id and a connection name, and had to
 * go and look up the upstream account and the scopes that had just been taken
 * away — at exactly the moment the record may be a tombstone.
 *
 * A grant revoked while `pending` has none of it, and that absence is the
 * honest answer rather than a blank: nothing was ever authorized.
 *
 * Copies, so that a sink which holds its argument cannot be handed a reference
 * into a record the caller is still working with.
 */
export function federationGrantAuditMetadata(
	grant: FederationGrant,
): Pick<FederationGrantAuditEvent, "connection" | "upstream" | "resource" | "scopes"> {
	if (!hasFederationGrantAuthorization(grant)) return { connection: grant.connection };
	return {
		connection: grant.connection,
		upstream: { ...grant.upstream },
		...(grant.resource === undefined ? {} : { resource: grant.resource }),
		scopes: [...grant.scopes],
	};
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
			correlationId: deps.correlationId ?? "",
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
