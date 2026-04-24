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
	role: "subject" | "actor";
}

/**
 * Validates a token presented in a Token Exchange request.
 *
 * Consumers register one validator per `subject_token_type` / `actor_token_type`
 * URI. Returning `null` signals a validation failure — the grant handler will
 * respond with `invalid_grant`. Throwing signals an infrastructure failure
 * (e.g. Redis unavailable) — the grant handler will respond with
 * `temporarily_unavailable` (503).
 */
export interface ExchangeTokenValidator {
	readonly tokenType: string;
	validate(token: string, context: ExchangeTokenValidationContext): Promise<ValidatedToken | null>;
}

/**
 * Structured representation of a validated exchange token.
 * `familyId` is populated only for self-issued access_tokens that carry a
 * `family_id` claim (used for cascading revoke inheritance).
 */
export interface ValidatedToken {
	sub: string;
	scope?: string;
	aud?: string | string[];
	familyId?: string;
	act?: Record<string, unknown>;
	claims: Record<string, unknown>;
}
