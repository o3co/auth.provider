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
 * What an audit event says about the grant it concerns (#593, D18).
 *
 * Its own module because three emitters need the same answer and they cannot
 * import each other: core's retrieval, core's revocation library call, and —
 * through the package boundary — the routes. A helper living in any one of
 * them would be the copy the other two drift from, which is what happened
 * before this existed.
 */

import { auditErrorText } from "../errors/envelope.mjs";
import type { FederationGrantAuditEvent } from "./retrieve.mjs";
import { type FederationGrant, hasFederationGrantAuthorization } from "./types.mjs";

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
 *
 * The upstream subject is the ID token's `sub`, stored as the IdP wrote it:
 * it is carried sanitised and capped (`auditErrorText`), here rather than in
 * a bridge, because every emitter takes it from here — core's retrieval and
 * revocation, whose `audit` seam a composer may fill with its own function,
 * and the routes' bridges. A well-formed subject is carried unchanged.
 */
export function federationGrantAuditMetadata(
	grant: FederationGrant,
): Pick<FederationGrantAuditEvent, "connection" | "upstream" | "resource" | "scopes"> {
	if (!hasFederationGrantAuthorization(grant)) return { connection: grant.connection };
	return {
		connection: grant.connection,
		// Projected, not spread: an event carries the established pair and
		// nothing else a record's object might hold (#611).
		upstream: { issuer: grant.upstream.issuer, subject: auditErrorText(grant.upstream.subject) },
		...(grant.resource === undefined ? {} : { resource: grant.resource }),
		scopes: [...grant.scopes],
	};
}
