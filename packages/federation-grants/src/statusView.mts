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
 * What a grant looks like from outside. See ADR
 * 2026-09-17-federation-grants-offline-delegation, D9.
 *
 * An allowlist, field by field, not a record with fields deleted: the rest of
 * the record (consent session, intent handle, identity fingerprints, version,
 * last failed refresh stamp) is no caller's business, and a spread would
 * disclose any field added later. A field a record does not have is
 * **omitted**, not reported empty: `"expires_at": null` would invite a client
 * to compare it with something.
 */

import {
	type EffectiveFederationGrantStatus,
	type FederationGrant,
	federationGrantEffectiveExpiry,
	hasFederationGrantAuthorization,
} from "@o3co/auth-provider-core";

/** UTC, to the millisecond, as every other instant this product puts on the wire. */
const instant = (value: Date): string => value.toISOString();

export function federationGrantStatusView(
	grant: FederationGrant,
	status: EffectiveFederationGrantStatus,
	maxExpiresInMs: number,
	/**
	 * Whether the client may still use this grant's connection.
	 *
	 * A grant that has ENDED is described either way: that answer lets a client
	 * stop asking. But a client an operator has taken off the allowlist is not
	 * handed the upstream account, the consented scope set or the dates, so
	 * removing it changes the payload and not only the status code.
	 */
	permitted: boolean,
): Readonly<Record<string, unknown>> {
	const reason = (status as { reason?: unknown }).reason;
	const authorized = hasFederationGrantAuthorization(grant) && permitted;
	return {
		grant_id: grant.id,
		status: status.status,
		// Omitted for the statuses that have none — `active`, `pending` and
		// `connection_not_configured` — rather than carried as an empty string.
		...(typeof reason === "string" ? { reason } : {}),
		sub: grant.subject,
		client_id: grant.clientId,
		connection: grant.connection,
		created_at: instant(grant.createdAt),
		...(authorized
			? {
					upstream: { issuer: grant.upstream.issuer, subject: grant.upstream.subject },
					// The authorization's scopes: what the user consented the client
					// to, not what one cached token happens to carry. The two differ
					// as soon as an upstream answers a refresh with fewer.
					scope: grant.scopes.join(" "),
					...(grant.resource === undefined ? {} : { resource: grant.resource }),
					authorized_at: instant(grant.authorizedAt),
					// Effective, not stored: computed from `maxExpiresIn` as it
					// is configured NOW, so lowering the maximum moves this earlier
					// for grants that already exist — possibly into the past — and
					// raising it brings it back, never beyond the stored expiry.
					expires_at: instant(federationGrantEffectiveExpiry(grant, maxExpiresInMs)),
				}
			: {}),
		...(grant.lastUsedAt === undefined || !permitted
			? {}
			: { last_used_at: instant(grant.lastUsedAt) }),
	};
}
