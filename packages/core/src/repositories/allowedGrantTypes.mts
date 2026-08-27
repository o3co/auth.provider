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
 * Individual grants MAY layer a stricter rule on top. `client_credentials`
 * and the WebAuthn grant both deny by absence, deliberately, so that
 * machine-to-machine access is never acquired by omission. The two rules
 * compose to the stricter of the pair, because either can reject and only
 * the absent case distinguishes them.
 *
 * Exact string comparison: `grant_type` is case-sensitive, and extension
 * grants are URIs (RFC 6749 §4.5), where a prefix or case-folded match would
 * be a namespace confusion rather than a convenience.
 */
export const isGrantTypeAllowed = (
	allowedGrantTypes: readonly string[] | undefined,
	grantType: string,
): boolean => allowedGrantTypes === undefined || allowedGrantTypes.includes(grantType);
