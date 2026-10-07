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
 * The token-exchange validator port. `oauth-token-exchange` registers
 * validators as `exchangeTokenValidators` contributions and the boot planner
 * hands them back; the contract lives in core because core may not import
 * that package. The consuming grant stays there.
 */

/**
 * Role of a token within a Token Exchange request.
 * - "subject": the token being exchanged (`subject_token`)
 * - "actor":   the token of the party performing the exchange (`actor_token`)
 */
export interface ExchangeTokenValidationContext {
	readonly role: "subject" | "actor";
	/**
	 * Reserved; the built-in grant handler never sets it. It checks the
	 * request's audience and resources against the client's registration and
	 * the subject token's audience before the policy runs, and against the
	 * issued audience after it, so a validator must not rely on this.
	 */
	readonly requestedResources?: readonly string[];
}

export interface ExchangeTokenValidator {
	/**
	 * Validates a token presented in a Token Exchange request. Register one
	 * validator per `subject_token_type` / `actor_token_type` URI.
	 *
	 * Return `null` for a validation failure (answered `invalid_request`, RFC
	 * 8693 §2.2.2); throw for an infrastructure failure (answered
	 * `temporarily_unavailable`, 503). Validators MAY apply different rules per
	 * `context.role` (e.g. a stricter issuer allowlist for actors) but SHOULD
	 * default to identical validation.
	 *
	 * For a subject token and an actor token, return the `aud` and the
	 * `claims.azp` the token carries: the grant reads them to check that the
	 * token names the calling client (see {@link ValidatedToken}).
	 */
	validate(token: string, context: ExchangeTokenValidationContext): Promise<ValidatedToken | null>;
}

/**
 * A validated exchange token. The structured fields are the canonical values
 * the grant handler consumes and MUST equal their projections in `claims`
 * (the raw payload, for policy hooks' custom claim forwarding) when both are
 * present; validators enforce this.
 *
 *   - `sub` (required): the subject of the issued token.
 *   - `claims` (required, may be `{}`). `claims.azp`, the party the token
 *     was issued to, is read by the check described under `aud`.
 *   - `scope`: enables scope narrowing; absent means no declared scope.
 *   - `aud`: the token's audience. For a subject token and an actor token,
 *     the grant reads it, with `claims.azp`, to check that the token names
 *     the calling client: the client's id is `claims.azp` or is in `aud`. A
 *     token whose answer carries neither is refused, unless the client's
 *     registration sets `allowExchangeOfTokensIssuedToOthers`. Also enables
 *     aud propagation for single-aud subjects.
 *   - `familyId`: this provider's refresh-token family, for a token issued
 *     under one. Checked against the family store (refused when none is
 *     wired) and copied into the issued token, so a family revocation reaches
 *     it too.
 *   - `sid`: the `UserSession` this provider minted the token from (its `sid`,
 *     or an exchanged token's `liveness_sid`). Checked for liveness when a
 *     user-session store is wired, and carried into the issued token as
 *     `liveness_sid`, never `sid`, so a logout ends the exchanged token too.
 *   - `act`: nested actor chain from a prior exchange (RFC 8693 §4.1).
 *   - `may_act`: the subject's delegation constraint. The handler reads the
 *     raw `claims.may_act`, so a malformed claim is handled fail-closed.
 *
 * `familyId` and `sid` left only in `claims` are neither checked nor
 * inherited. Leave them unset (an empty string counts as unset) for foreign
 * tokens, whose families and sessions this provider's stores do not hold.
 */
export interface ValidatedToken {
	readonly sub: string;
	readonly scope?: string;
	readonly aud?: string | readonly string[];
	readonly familyId?: string;
	readonly sid?: string;
	readonly act?: Readonly<Record<string, unknown>>;
	readonly may_act?:
		| Readonly<Record<string, unknown>>
		| readonly Readonly<Record<string, unknown>>[];
	readonly claims: Readonly<Record<string, unknown>>;
}
