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
 * under. Compared with the current connection on every read and never
 * persisted as a status, so reverting a mistaken edit restores the grants.
 *
 * The hash input is JSON of a fixed-shape array (no value can run into its
 * neighbour), led by a tag that keeps the two fingerprints apart.
 *
 * A PERSISTED FORMAT: changing what is hashed makes every grant read as
 * `connection_identity_changed`, which is terminal. Hence the versioned tag
 * and the known-answer tests.
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
 * When this differs the grant reads as `reauthorization_required` /
 * `connection_changed` and is reauthorized in place. Narrowing the scopes
 * changes it too: asking again is always safe.
 *
 * Deliberately excluded: `maxAccessTokenLifetime` (judged at its current
 * value on every disclosure; hashing it would turn a config slip into a
 * reconnect for every user) and `allowScopeSubsets` (only governs new
 * intents).
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
