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

import type { UserSessionClaims } from "@o3co/auth-provider-core";

/**
 * Top-level claim under which an upstream IdP's mapped claims are recorded,
 * keyed by provider name: `claims.federated["google"].hd`.
 *
 * Nothing here is authoritative for this deployment. It is the IdP's assertion,
 * kept verbatim so a consumer that wants a federated value can take it
 * deliberately, rather than receiving it merged into the envelope it also uses
 * for authorization.
 *
 * The key cannot collide with a locally-sourced claim: `extractUserClaims`
 * picks a fixed five fields off `User` and this is not one of them, so
 * `claims.federated` is always written by the federation callback route.
 */
export const FEDERATED_CLAIMS_KEY = "federated";

/**
 * The only claims a federated profile may contribute to the top-level claims
 * envelope, and then only where the local record left the field absent.
 *
 * Deliberately excluded:
 *
 * - **`groups`** (and any `roles` / `scope` / `permissions` an adapter invents)
 *   — authorization input. An IdP that could write these would be granting
 *   itself local authorization, which is #279.
 * - **`emailVerified`** — Store-owned state since #297, readable by
 *   `oauth.requireEmailVerified` as a gate on token issuance, and surfaced to
 *   relying parties as the signed `email_verified` claim. An upstream IdP
 *   verifies an address *it* controls; it has no knowledge of the local
 *   account's address, which the `provider:sub` linkage never forces to match.
 *   A deployment that wants to act on the IdP's assertion reads
 *   `claims.federated[<provider>].emailVerified` and publishes the result on
 *   the `User` — the Store is where #297 put the field, and that is the opt-in.
 *
 * Exported so a deployment can assert on the set from its own tests.
 */
export const PROMOTABLE_FEDERATED_CLAIMS = ["email", "name", "picture"] as const;

/** Per-provider record of what each upstream IdP asserted, verbatim. */
export interface FederatedClaimsNamespace {
	readonly [providerName: string]: Readonly<Record<string, unknown>>;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * Merge a federated profile's mapped claims into the locally authoritative
 * claims envelope, under a single precedence rule: **the local record wins,
 * and everything else is namespaced** (#279).
 *
 * Federation is an authentication signal, not an authorization one. The local
 * account is already resolved — the callback route looked it up by
 * `provider:sub` — so any field the local `User` declares is this deployment's
 * answer, and an upstream IdP does not get to replace it. Where the local
 * record is silent on a promotable profile claim, the federated value fills the
 * gap; everything else is recorded under {@link FEDERATED_CLAIMS_KEY}.
 *
 * Promotion is written as one named read per promotable claim rather than a
 * loop over {@link PROMOTABLE_FEDERATED_CLAIMS}. That is the point: there is no
 * expression in this function that can carry a key the compiler has not seen
 * into the top-level envelope, so `groups` — or a `roles` an adapter invents —
 * cannot reach it by any input, only by someone writing a new line here.
 *
 * `mappedClaims` is typed `unknown` on purpose. A federation adapter is a
 * third-party extension point reached across an untyped boundary; a hostile or
 * simply broken one returning `null`, an array or a string must not be able to
 * corrupt the envelope.
 */
export const mergeFederatedClaims = ({
	localClaims,
	providerName,
	mappedClaims,
}: {
	readonly localClaims: UserSessionClaims;
	readonly providerName: string;
	readonly mappedClaims: unknown;
}): UserSessionClaims => {
	const mapped = isRecord(mappedClaims) ? mappedClaims : {};
	const merged: Record<string, unknown> = { ...localClaims };

	if (merged.email === undefined && typeof mapped.email === "string") {
		merged.email = mapped.email;
	}
	if (merged.name === undefined && typeof mapped.name === "string") {
		merged.name = mapped.name;
	}
	if (merged.picture === undefined && typeof mapped.picture === "string") {
		merged.picture = mapped.picture;
	}

	// The namespace carries the full mapped snapshot, including values that were
	// also promoted and values that lost to a local claim — the record of what
	// the IdP said stays complete and separate from what this deployment holds.
	if (Object.keys(mapped).length > 0) {
		merged[FEDERATED_CLAIMS_KEY] = {
			[providerName]: { ...mapped },
		} satisfies FederatedClaimsNamespace;
	}

	return merged as UserSessionClaims;
};
