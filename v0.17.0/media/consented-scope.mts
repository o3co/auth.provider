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
 * What a completed federation authorization consented to, as one canonical
 * space-delimited string, or `undefined` when nothing did:
 *
 * 1. the upstream's answer (`FederationProfile.scope`) when present — RFC
 *    6749 §5.1 requires it whenever the grant differs from the request;
 * 2. else what the provider asked for (`FederationProvider.scope`) — §3.3
 *    lets the answer be omitted only when it equals the request, so silence
 *    means "as requested", not "no scope" (Apple sends none).
 *
 * Decided by presence, not usefulness: an answered `""` claims nothing
 * rather than falling back to the request. Adapter input is checked before it
 * is believed (a non-string names nothing), which also keeps a bad field out
 * of the sealed Redis record. The two branches may use different
 * vocabularies (Google answers full URLs for its short aliases); that is
 * sound because a record only ever compares with itself. Core's
 * `consentedScopes` applies the same idea to federation grants.
 */
import { parseScopeTokens } from "@o3co/auth-provider-core";

export function consentedScope(
	answered: unknown,
	requested: readonly string[] | undefined,
): string | undefined {
	// Present is not absent: an answer naming nothing usable must not fall back
	// to the request, which would record unconsented scopes as the ceiling for
	// the life of the connection (fail-open).
	if (answered !== undefined) {
		const named = parseScopeTokens(answered);
		return named.length > 0 ? named.join(" ") : undefined;
	}
	// Parsed the same way, not merely filtered: an entry may itself be a
	// space-delimited list, or whitespace.
	const asked = [...new Set((requested ?? []).flatMap((entry) => parseScopeTokens(entry)))];
	return asked.length > 0 ? asked.join(" ") : undefined;
}
