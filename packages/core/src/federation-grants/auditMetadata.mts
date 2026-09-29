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
 * What an audit event says about the grant it concerns. Its own module so
 * that core's retrieval, core's revocation and the routes package share one
 * answer rather than drifting copies.
 */

import { auditErrorText } from "../errors/envelope.mjs";
import type { FederationGrantAuditEvent } from "./retrieve.mjs";
import { type FederationGrant, hasFederationGrantAuthorization } from "./types.mjs";

/**
 * What an event can say about the grant it concerns: the connection and,
 * once established, the upstream account, resource and scopes, so a
 * revocation event says *what access ended*. A grant still `pending` has
 * only its connection: nothing was ever authorized.
 *
 * Returns copies, so a sink that holds its argument never aliases the record.
 * The upstream `sub` is IdP-written, so it is sanitised and capped
 * (`auditErrorText`) here, where every emitter takes it from. See ADR
 * 2026-09-17-federation-grants-offline-delegation, D18.
 */
export function federationGrantAuditMetadata(
	grant: FederationGrant,
): Pick<FederationGrantAuditEvent, "connection" | "upstream" | "resource" | "scopes"> {
	if (!hasFederationGrantAuthorization(grant)) return { connection: grant.connection };
	return {
		connection: grant.connection,
		// Projected, not spread: an event carries the established pair and
		// nothing else a record's object might hold.
		upstream: { issuer: grant.upstream.issuer, subject: auditErrorText(grant.upstream.subject) },
		...(grant.resource === undefined ? {} : { resource: grant.resource }),
		scopes: [...grant.scopes],
	};
}
