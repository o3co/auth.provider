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
 * Whether a client's `allowedGrantTypes` permits `grantType`.
 *
 * This is the **central** rule, applied once at grant dispatch and at
 * `/authorize` so every current and future grant inherits it (#268).
 *
 *   - `undefined` (no allowlist declared) → allowed. Absence means
 *     "unrestricted", not "denied": the field post-dates the grants that
 *     ignore it, so treating absence as denial would revoke every grant from
 *     every registration written before it existed — a total outage on
 *     upgrade rather than a security fix.
 *   - declared → allowed iff `grantType` appears in it. An empty array
 *     therefore denies everything, which is what "this client may use no
 *     grant type" has always meant for this field.
 *
 * A grant MAY declare a stricter rule via
 * `GrantHandler.requiresExplicitGrantAllowlist` (#326): dispatch then denies
 * by absence for that grant — deliberately, so that machine-to-machine
 * access is never acquired by omission. `client_credentials` and the
 * WebAuthn grant declare it. The two rules compose to the stricter of the
 * pair, because either can reject and only the absent case distinguishes
 * them; both are enforced at dispatch, next to each other.
 *
 * `options.requireAllowlist` (#311) flips the absent case to denial for the
 * whole deployment — the counterpart of `requiresExplicitGrantAllowlist`,
 * which only a handler can declare and only for itself. Without it the secure
 * posture is opt-in *per registration*: an operator who wants deny-by-default
 * has to guarantee that every registration, now and in future, carries the
 * field, and nothing enforces that. It defaults off, because flipping the
 * default is the outage #268 was shaped to avoid; a deployment turns it on
 * once it has audited what it has registered.
 *
 * Absence denies outright rather than falling back to an implied set. RFC 7591
 * §2 does the latter — an omitted `grant_types` there means
 * `["authorization_code"]` alone — and that is good evidence absence should
 * not mean "everything", but an implied set is still a decision nobody wrote
 * down, which is the shape #363 exists to refuse. A deployment that turns this
 * on has said it audits its registrations, so it can name the grants.
 *
 * Exact string comparison: `grant_type` is case-sensitive, and extension
 * grants are URIs (RFC 6749 §4.5), where a prefix or case-folded match would
 * be a namespace confusion rather than a convenience.
 */
export const isGrantTypeAllowed = (
	allowedGrantTypes: readonly string[] | undefined,
	grantType: string,
	options?: { readonly requireAllowlist?: boolean },
): boolean =>
	allowedGrantTypes === undefined
		? options?.requireAllowlist !== true
		: allowedGrantTypes.includes(grantType);
