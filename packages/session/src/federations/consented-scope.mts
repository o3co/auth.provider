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
 * What a completed federation authorization consented to, as one
 * space-delimited string, or `undefined` when nothing did.
 *
 * Two readings, in the order RFC 6749 gives them:
 *
 * 1. What the upstream answered (`FederationProfile.scope`). §5.1 makes that
 *    field REQUIRED whenever the granted scope differs from the requested one,
 *    so when an upstream names a scope, that is what it granted.
 * 2. What the provider asked for (`FederationProvider.scope`). §3.3 makes the
 *    answer OPTIONAL only when it is identical to the request, so silence
 *    means "as requested" — not "no scope". Three of the four bundled adapters
 *    say nothing, and reading their silence as "no scope" would leave the
 *    record with no ceiling at all (#647).
 *
 * An adapter is a third-party extension point, so neither reading is believed
 * before it is checked (D5): a non-string, an empty string and a whitespace-only
 * string all name nothing. That check also protects the store — the Redis
 * adapter seals the record into one ciphertext and a non-string field would
 * only fail on the NEXT read, where it is indistinguishable from corruption
 * and the record is dropped.
 *
 * The result is canonical: parsed, de-duplicated and re-joined, so the value a
 * later refresh is judged against does not depend on the spacing an upstream
 * happened to use.
 *
 * The sibling concept in `@o3co/auth-provider-core`'s federation grants is
 * `consentedScopes` (`federation-grants/eligibility.mts`), which judges an
 * upstream token against the same kind of ceiling for grants that outlive a
 * session. One idea, two subsystems.
 */
export function consentedScope(
	answered: unknown,
	requested: readonly string[] | undefined,
): string | undefined {
	const named = parse(answered);
	if (named.length > 0) return named.join(" ");
	const asked = (requested ?? []).filter((entry) => typeof entry === "string" && entry !== "");
	return asked.length > 0 ? [...new Set(asked)].join(" ") : undefined;
}

const parse = (value: unknown): readonly string[] =>
	typeof value === "string" ? [...new Set(value.split(" ").filter((entry) => entry !== ""))] : [];
