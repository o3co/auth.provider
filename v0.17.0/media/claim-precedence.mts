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
 * keyed by provider name: `claims.federated?.["google"]?.hd`. Nothing here is
 * authoritative for this deployment: it is the IdP's assertion, kept verbatim
 * so a consumer takes a federated value deliberately rather than receiving it
 * merged into the envelope it also uses for authorization.
 *
 * **The key is optional — read it with a presence check.**
 * {@link mergeFederatedClaims} writes it only when the provider mapped at least
 * one claim, and a session carries only the provider that authenticated it
 * (README, "Claim precedence"). Do not "fix" this into always writing the key:
 * `federated: {}` would say only that a code path ran, while absence says
 * "this IdP asserted nothing".
 *
 * When present it came from this merge, never from the Store, and cannot
 * collide with a locally-sourced claim: `extractUserClaims` picks a fixed five
 * fields off `User` (`email`, `emailVerified`, `name`, `picture`, `groups`).
 */
export const FEDERATED_CLAIMS_KEY = "federated";

/**
 * The only claims a federated profile may contribute to the top-level claims
 * envelope, and then only where the local record left the field absent and the
 * mapped value is a string. A promotable claim of any other type is dropped:
 * an adapter is reached across an untyped boundary, and a `name` that is an
 * object would reach a signed token.
 *
 * Deliberately excluded:
 *
 * - **`groups`** (and any `roles` / `scope` / `permissions` an adapter invents):
 *   authorization input. An IdP that could write these would be granting itself
 *   local authorization.
 * - **`emailVerified`**: Store-owned state, readable by
 *   `oauth.requireEmailVerified` as a gate on token issuance and surfaced to
 *   relying parties as the signed `email_verified` claim. An upstream IdP
 *   verifies an address *it* controls, which the `provider:sub` linkage never
 *   forces to match the local account's. A deployment that wants to act on the
 *   IdP's assertion reads `claims.federated?.[<provider>]?.emailVerified` and
 *   publishes the result on the `User`.
 *
 * Exported so a deployment can assert on the set from its own tests.
 */
export const PROMOTABLE_FEDERATED_CLAIMS = ["email", "name", "picture"] as const;

/**
 * What an upstream IdP asserted, keyed by provider name and shallow-copied from
 * the `mapClaims` return so a later mutation by the adapter cannot reach a
 * stored session.
 *
 * The index signature carries no guarantee that a given provider is present: a
 * session created by the federation callback holds the single provider that
 * authenticated it. The map shape is for a consumer merging claims across
 * providers.
 */
export interface FederatedClaimsNamespace {
	readonly [providerName: string]: Readonly<Record<string, unknown>>;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * Merge a federated profile's mapped claims into the locally authoritative
 * claims envelope: **the local record wins, and everything else is
 * namespaced** (README, "Claim precedence").
 *
 * Federation is an authentication signal, not an authorization one. The local
 * account is already resolved by `provider:sub`, so any field the local `User`
 * declares stands. Where it is silent on a claim in
 * {@link PROMOTABLE_FEDERATED_CLAIMS}, a string mapped value fills the gap. The
 * mapped claims are also recorded in full under {@link FEDERATED_CLAIMS_KEY},
 * when at least one was mapped.
 *
 * Returns a fresh envelope. Neither `localClaims` nor `mappedClaims` is
 * mutated, and the namespaced snapshot is a shallow copy.
 *
 * Promotion is one named read per promotable claim, not a loop, so no
 * expression here can carry a key the compiler has not seen into the top-level
 * envelope: `groups`, or a `roles` an adapter invents, can reach it only by
 * someone writing a new line here.
 *
 * `mappedClaims` is `unknown` on purpose: an adapter is reached across an
 * untyped boundary, and a hostile or broken one returning `null`, an array or
 * a string must not be able to corrupt the envelope.
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

	// The full mapped snapshot, promoted or not. The guard is the documented
	// contract on FEDERATED_CLAIMS_KEY, not an optimization: a provider that
	// maps nothing leaves the key absent rather than writing `federated: {}`.
	if (Object.keys(mapped).length > 0) {
		merged[FEDERATED_CLAIMS_KEY] = {
			[providerName]: { ...mapped },
		} satisfies FederatedClaimsNamespace;
	}

	return merged as UserSessionClaims;
};
