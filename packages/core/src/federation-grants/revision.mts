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

import { createHash } from "node:crypto";
import type { FederationGrantConnection } from "./types.mjs";

/**
 * The two fingerprints a grant records of the connection it was authorized
 * under (#593, D4). Both are compared with the current connection on every
 * read, and never persisted as a status, so reverting a mistaken edit restores
 * the grants it had cut off.
 *
 * What is hashed is JSON of a fixed-shape array: JSON quotes and escapes every
 * string, so no value can run into its neighbour, and a leading tag keeps the
 * two fingerprints apart even if their fields ever coincided.
 *
 * Both are a PERSISTED FORMAT. They are stored on every grant, and a change to
 * what is hashed makes every grant read as `connection_identity_changed`,
 * which is terminal. The tag carries a version for that reason, and the tests
 * pin a known answer.
 */
function fingerprint(tag: string, fields: readonly unknown[]): string {
	return createHash("sha256")
		.update(JSON.stringify([tag, ...fields]))
		.digest("base64url");
}

/**
 * Who the upstream is, and as whom auth.provider speaks to it.
 *
 * When this differs, the upstream subject the grant recorded can no longer be
 * compared — many IdPs issue a `sub` per client — so a reauthorization could
 * never pass its account check. The grant reads as
 * `connection_identity_changed`, and the application asks for a new one.
 */
export function federationGrantIdentityRevision(
	connection: Pick<FederationGrantConnection, "upstreamIssuer" | "upstreamClientId">,
): string {
	return fingerprint("identity/v1", [connection.upstreamIssuer, connection.upstreamClientId]);
}

/**
 * What is asked of the upstream, for which resource, in which environment.
 *
 * When this differs the grant reads as `reauthorization_required` /
 * `connection_changed` and is reauthorized in place. Narrowing the scopes
 * changes it too: reusing consent across a narrowing would be sound, but
 * proving "narrower" for every field is not worth it, and asking again is
 * always safe.
 *
 * `maxAccessTokenLifetime` and `allowScopeSubsets` are deliberately not here.
 * The first is judged against its current value before every disclosure, so
 * tightening it takes effect on the next call; making it part of this
 * fingerprint would turn a configuration slip into a reconnect for every
 * user. The second only governs what a new intent may ask for.
 */
export function federationGrantAuthorizationRevision(
	connection: Pick<
		FederationGrantConnection,
		"resource" | "scopes" | "boundary" | "authorizationParams"
	>,
): string {
	const scopes = [...new Set(connection.scopes)].sort();
	const params = Object.entries(connection.authorizationParams ?? {}).sort(([a], [b]) =>
		a < b ? -1 : a > b ? 1 : 0,
	);
	return fingerprint("authorization/v1", [
		connection.resource ?? null,
		scopes,
		connection.boundary,
		params,
	]);
}
