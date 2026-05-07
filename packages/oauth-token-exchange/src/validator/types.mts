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
 * Role of a token within a Token Exchange request.
 * - "subject": the token being exchanged (`subject_token`)
 * - "actor":   the token of the party performing the exchange (`actor_token`)
 */
export interface ExchangeTokenValidationContext {
	readonly role: "subject" | "actor";
}

export interface ExchangeTokenValidator {
	/**
	 * Validates a token presented in a Token Exchange request.
	 *
	 * Consumers register one validator per `subject_token_type` / `actor_token_type`
	 * URI.
	 *
	 * Return contract:
	 *   - Returning `null` signals a validation failure — the grant handler will
	 *     respond with `invalid_grant`.
	 *   - Throwing signals an infrastructure failure (e.g. Redis unavailable) —
	 *     the grant handler will respond with `temporarily_unavailable` (503).
	 *
	 * The `context.role` hints whether the token is being presented as the
	 * `subject` (token being exchanged) or `actor` (delegation actor).
	 * Validators MAY apply different rules per role (e.g. stricter issuer
	 * allowlist for actor) but SHOULD default to identical validation.
	 */
	validate(token: string, context: ExchangeTokenValidationContext): Promise<ValidatedToken | null>;
}

/**
 * Structured representation of a validated exchange token.
 *
 * The structured fields (`sub`, `scope`, `aud`, `familyId`, `act`) are the
 * canonical values the grant handler consumes. `claims` carries the raw JWT
 * payload for policy hooks that need custom claim forwarding.
 *
 * Invariant: structured fields are projections of `claims`. When both are
 * present they MUST be equal. Validators are responsible for enforcing this.
 * `familyId` is populated only for self-issued access_tokens that carry a
 * `family_id` claim (used for cascading revoke inheritance).
 *
 * Required fields:
 *   - `sub`: mandatory. Used as the subject of the newly issued token.
 *   - `claims`: mandatory (may be empty `{}`). Passed to policy hooks for
 *     custom claim forwarding.
 *
 * Optional fields (populate when known):
 *   - `scope`: enables scope narrowing. Absent means no declared scope.
 *   - `aud`: enables aud propagation for single-aud subjects.
 *   - `familyId`: enables cascading revoke inheritance. Only meaningful for
 *     self-issued access_tokens.
 *   - `act`: nested actor chain from a prior exchange. The grant handler
 *     preserves this when applicable (RFC 8693 §4.1).
 */
export interface ValidatedToken {
	readonly sub: string;
	readonly scope?: string;
	readonly aud?: string | readonly string[];
	readonly familyId?: string;
	readonly act?: Readonly<Record<string, unknown>>;
	readonly claims: Readonly<Record<string, unknown>>;
}
