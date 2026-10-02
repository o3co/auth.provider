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
 * to compare it with something. A stored date that holds no instant is not
 * described at all: the view is refused, naming the field.
 */

import {
	type EffectiveFederationGrantStatus,
	type FederationGrant,
	federationGrantEffectiveExpiry,
	hasFederationGrantAuthorization,
} from "@o3co/auth-provider-core";

/** A field the view could not date, by its name on the wire. */
export type FederationGrantStatusDateField =
	| "created_at"
	| "authorized_at"
	| "expires_at"
	| "last_used_at";

/** The view, or the first date it could not put on the wire. */
export type FederationGrantStatusViewResult =
	| { readonly ok: true; readonly view: Readonly<Record<string, unknown>> }
	| { readonly ok: false; readonly field: FederationGrantStatusDateField };

/**
 * UTC, to the millisecond, as every other instant this product puts on the
 * wire, through the `Date` intrinsic rather than a method the value may
 * override; `undefined` for a value that holds no instant.
 */
const instant = (value: unknown): string | undefined => {
	try {
		return Date.prototype.toISOString.call(value);
	} catch {
		return undefined;
	}
};

const undated = (field: FederationGrantStatusDateField): FederationGrantStatusViewResult => ({
	ok: false,
	field,
});

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
): FederationGrantStatusViewResult {
	const reason = (status as { reason?: unknown }).reason;
	const createdAt = instant(grant.createdAt);
	if (createdAt === undefined) return undated("created_at");

	let authorization: Readonly<Record<string, unknown>> = {};
	if (hasFederationGrantAuthorization(grant) && permitted) {
		const authorizedAt = instant(grant.authorizedAt);
		if (authorizedAt === undefined) return undated("authorized_at");
		// Effective, not stored: computed from `maxExpiresIn` as it is
		// configured NOW, so lowering the maximum moves this earlier for grants
		// that already exist — possibly into the past — and raising it brings
		// it back, never beyond the stored expiry.
		const expiresAt = instant(federationGrantEffectiveExpiry(grant, maxExpiresInMs));
		if (expiresAt === undefined) return undated("expires_at");
		authorization = {
			upstream: { issuer: grant.upstream.issuer, subject: grant.upstream.subject },
			// The authorization's scopes: what the user consented the client to,
			// not what one cached token happens to carry. The two differ as soon
			// as an upstream answers a refresh with fewer.
			scope: grant.scopes.join(" "),
			...(grant.resource === undefined ? {} : { resource: grant.resource }),
			authorized_at: authorizedAt,
			expires_at: expiresAt,
		};
	}

	let lastUse: Readonly<Record<string, unknown>> = {};
	if (grant.lastUsedAt !== undefined && permitted) {
		const lastUsedAt = instant(grant.lastUsedAt);
		if (lastUsedAt === undefined) return undated("last_used_at");
		lastUse = { last_used_at: lastUsedAt };
	}

	return {
		ok: true,
		view: {
			grant_id: grant.id,
			status: status.status,
			// Omitted for the statuses that have none — `active`, `pending` and
			// `connection_not_configured` — rather than carried as an empty string.
			...(typeof reason === "string" ? { reason } : {}),
			sub: grant.subject,
			client_id: grant.clientId,
			connection: grant.connection,
			created_at: createdAt,
			...authorization,
			...lastUse,
		},
	};
}
