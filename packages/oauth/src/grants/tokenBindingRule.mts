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
 * The refresh-token binding rule, as the grants that mint a refresh token
 * read it: `bindConfidentialClientRefreshTokens` from core's
 * `tokenBindingSettings` slot, which core fills frozen from
 * `core.tokenBinding`. Read once, when a grant is built.
 */

/**
 * Whether a confidential client's refresh token is bound to the key or
 * certificate its request was bound with. Throws a `TypeError` naming the
 * slot and `grant` when the slot is not filled with a boolean rule: a deps
 * built without it, or with a value whose rule is not a boolean, fails at
 * composition, before any request.
 */
export function bindConfidentialClientRefreshTokensFrom(
	tokenBindingSettings: unknown,
	grant: string,
): boolean {
	const rule = (
		tokenBindingSettings as
			| { readonly bindConfidentialClientRefreshTokens?: unknown }
			| null
			| undefined
	)?.bindConfidentialClientRefreshTokens;
	if (typeof rule !== "boolean") {
		throw new TypeError(
			`${grant}: the tokenBindingSettings slot is not filled with a boolean bindConfidentialClientRefreshTokens`,
		);
	}
	return rule;
}
