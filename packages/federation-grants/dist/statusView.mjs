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
 * What a grant looks like from outside (#593, D9).
 *
 * An allowlist, written out field by field, rather than a record with a few
 * things deleted. What a grant holds includes the consent session it was made
 * in, the intent handle that made it, the fingerprints its identity is pinned
 * to, its version and the stamp of its last failed refresh — none of which is
 * a caller's business, and all of which a spread would disclose the day
 * somebody adds a field to the record.
 *
 * A field a record does not have is **omitted**, not reported empty: a pending
 * grant has no upstream account and no expiry because it has not been
 * consented to yet, and `"expires_at": null` would invite a client to compare
 * it with something.
 */
import { federationGrantEffectiveExpiry, hasFederationGrantAuthorization, } from "@o3co/auth-provider-core";
/** UTC, to the millisecond, as every other instant this product puts on the wire. */
const instant = (value) => value.toISOString();
export function federationGrantStatusView(grant, status, maxExpiresInMs, 
/**
 * Whether the client may still use this grant's connection.
 *
 * A grant that has ENDED is described whether or not the client may still
 * use its connection — that answer is what lets a client stop asking. What
 * it is not is a reason to keep handing back the upstream account, the
 * consented scope set and the dates to a client an operator has just taken
 * off the allowlist. Review asked the question the design had not: removing
 * a client from the allowlist is an operator's lever, and a lever that
 * changes the status code but not the payload is half a lever.
 */
permitted) {
    const reason = status.reason;
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
                // Effective, not stored (D3): computed from `maxExpiresIn` as it
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
