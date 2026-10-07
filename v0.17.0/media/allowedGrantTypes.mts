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
 * Whether a client's `allowedGrantTypes` permits `grantType`: the central
 * rule, applied at grant dispatch and at `/authorize` so every grant inherits
 * it.
 *
 *   - `undefined` (no allowlist) → allowed. The field post-dates the grants,
 *     so denying on absence would revoke every grant from older registrations
 *     on upgrade.
 *   - declared → allowed iff `grantType` is in it; an empty array denies all.
 *
 * Two stricter rules deny on absence instead: a grant's
 * `GrantHandler.requiresExplicitGrantAllowlist` (`client_credentials`,
 * WebAuthn), so machine-to-machine access is never acquired by omission; and
 * `options.requireAllowlist`, for a whole deployment that has audited its
 * registrations (off by default, to avoid that upgrade outage). Absence then
 * denies outright rather than implying a set as RFC 7591 §2 does: an implied
 * set is a decision nobody wrote down.
 *
 * Exact string comparison: `grant_type` is case-sensitive, and extension
 * grants are URIs (RFC 6749 §4.5), where a prefix or case-folded match would
 * be namespace confusion.
 */
export const isGrantTypeAllowed = (
	allowedGrantTypes: readonly string[] | undefined,
	grantType: string,
	options?: { readonly requireAllowlist?: boolean },
): boolean =>
	allowedGrantTypes === undefined
		? options?.requireAllowlist !== true
		: allowedGrantTypes.includes(grantType);
