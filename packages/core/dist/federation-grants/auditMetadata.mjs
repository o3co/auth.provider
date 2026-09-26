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
import { hasFederationGrantAuthorization } from "./types.mjs";
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
export function federationGrantAuditMetadata(grant) {
    if (!hasFederationGrantAuthorization(grant))
        return { connection: grant.connection };
    return {
        connection: grant.connection,
        // Projected, not spread: an event carries the established pair and
        // nothing else a record's object might hold (#611).
        upstream: { issuer: grant.upstream.issuer, subject: grant.upstream.subject },
        ...(grant.resource === undefined ? {} : { resource: grant.resource }),
        scopes: [...grant.scopes],
    };
}
