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
 * Top-level claim under which an upstream IdP's mapped claims are recorded,
 * keyed by provider name: `claims.federated?.["google"]?.hd`.
 *
 * Nothing here is authoritative for this deployment. It is the IdP's assertion,
 * kept verbatim so a consumer that wants a federated value can take it
 * deliberately, rather than receiving it merged into the envelope it also uses
 * for authorization.
 *
 * **The key is optional — read it with a presence check.**
 * {@link mergeFederatedClaims} writes it only when the provider actually mapped
 * at least one claim, so it is absent on a session whose provider implements no
 * `SupportsClaimMapping`, and on one whose `mapClaims` returned `{}` or a value
 * that is not an object. `claims.federated?.[name]?.groups`, never
 * `claims.federated[name].groups`. The provider key is likewise not guaranteed:
 * a session carries the one provider that authenticated it, not every provider
 * the deployment registered.
 *
 * The omission is deliberate and should not be "fixed" into always writing the
 * key. An empty `federated: {}` would sit in the envelope of every session
 * created by a provider that maps nothing, saying only that a code path ran;
 * absence says "this IdP asserted nothing", which is the same absent-is-not-a-
 * value discipline #297 established for `emailVerified`.
 *
 * When the key *is* present, it came from this merge and never from the Store:
 * it cannot collide with a locally-sourced claim, because `extractUserClaims`
 * picks a fixed five fields off `User` (`email`, `emailVerified`, `name`,
 * `picture`, `groups`) and this is not one of them.
 */
export const FEDERATED_CLAIMS_KEY = "federated";
/**
 * The only claims a federated profile may contribute to the top-level claims
 * envelope, and then only where the local record left the field absent and the
 * mapped value is a string. A promotable claim whose mapped value is any other
 * type is dropped rather than promoted — an adapter is reached across an
 * untyped boundary, and a `name` that is an object would reach a signed token.
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
 *   `claims.federated?.[<provider>]?.emailVerified` and publishes the result on
 *   the `User` — the Store is where #297 put the field, and that is the opt-in.
 *
 * Exported so a deployment can assert on the set from its own tests.
 */
export const PROMOTABLE_FEDERATED_CLAIMS = ["email", "name", "picture"];
const isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
/**
 * Merge a federated profile's mapped claims into the locally authoritative
 * claims envelope, under a single precedence rule: **the local record wins,
 * and everything else is namespaced** (#279).
 *
 * Federation is an authentication signal, not an authorization one. The local
 * account is already resolved — the callback route looked it up by
 * `provider:sub` — so any field the local `User` declares is this deployment's
 * answer, and an upstream IdP does not get to replace it. Where the local
 * record is silent on a claim in {@link PROMOTABLE_FEDERATED_CLAIMS}, a string
 * mapped value fills the gap.
 *
 * The mapped claims are *also* recorded under {@link FEDERATED_CLAIMS_KEY} in
 * full — the promoted values, the values that lost to a local claim, and the
 * ones that were never promotable — so the record of what the IdP said stays
 * complete and stays separate from what this deployment holds. That key is
 * written only when at least one claim was mapped; see
 * {@link FEDERATED_CLAIMS_KEY} for why absence rather than `{}`, and for the
 * presence check a consumer therefore owes it.
 *
 * Returns a fresh envelope. Neither `localClaims` nor `mappedClaims` is
 * mutated, and the namespaced snapshot is a shallow copy.
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
export const mergeFederatedClaims = ({ localClaims, providerName, mappedClaims, }) => {
    const mapped = isRecord(mappedClaims) ? mappedClaims : {};
    const merged = { ...localClaims };
    if (merged.email === undefined && typeof mapped.email === "string") {
        merged.email = mapped.email;
    }
    if (merged.name === undefined && typeof mapped.name === "string") {
        merged.name = mapped.name;
    }
    if (merged.picture === undefined && typeof mapped.picture === "string") {
        merged.picture = mapped.picture;
    }
    // The namespace carries the full mapped snapshot — promoted values, values
    // that lost to a local claim, and values that were never promotable alike.
    //
    // The guard is load-bearing, not an optimization: a provider that maps
    // nothing leaves the key absent rather than writing `federated: {}`, so
    // "this IdP asserted nothing" reads as absence instead of as an empty object
    // in every such session's envelope. Consumers must therefore presence-check
    // the key — which is the documented contract on FEDERATED_CLAIMS_KEY, so
    // removing this guard would be a contract change, not a simplification.
    if (Object.keys(mapped).length > 0) {
        merged[FEDERATED_CLAIMS_KEY] = {
            [providerName]: { ...mapped },
        };
    }
    return merged;
};
