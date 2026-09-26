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
 * RFC 8707 resource indicators — the shared reading of the `resource` parameter
 * (and of RFC 8693's `audience`, the other target parameter), the audience a
 * request derives from it, and the check that an issued audience represents
 * it.
 *
 * Read by the oauth package's `client_credentials`, `refresh_token`,
 * `authorization_code` and jwt-bearer grants and `/authorize`, by the
 * WebAuthn grant, which forwards `resource` to `grantPolicy`, and by the
 * token-exchange grant, which reads `resource` and `audience` strictly. Those
 * packages do not depend on one another, so the rule lives in core rather
 * than in a copy per package. The home is mapped in
 * `docs/design-vocabulary.md` and guarded by `designVocabulary.drift.test.mts`.
 *
 * Pure functions over a parsed parameter bag: no HTTP, no Express.
 *
 * No comma-splitting is performed: RFC 8707 §5.4 treats each `resource`
 * value as a URI and URIs may legally contain commas, so splitting would
 * silently corrupt valid resource indicators.
 */

/**
 * Reads a target parameter — RFC 8707 `resource`, or RFC 8693 `audience` — as
 * a form or JSON body delivers it: the values it names, or `null` when it is
 * malformed.
 *
 * - Absent, `null` or `""`: `[]`, nothing named. RFC 6749 §3.2 has a
 *   parameter sent without a value treated as omitted.
 * - A string: that one value, kept whole.
 * - An array of strings (a repeated form parameter, or a JSON array): its
 *   non-empty entries, in order, so the array shape agrees with the string
 *   shape on what names nothing. `resource=&resource=https://x` reaches
 *   Express as `["", "https://x"]`; an empty entry surviving into the
 *   `invalid_target` check would be refused under an empty name. All-empty is
 *   `[]`.
 * - Anything else — a number, a boolean, an object, a nested array, an array
 *   holding a non-string — `null`: malformed. RFC 8707 §2 answers a value the
 *   server "fails to parse" with `invalid_target`. Nothing is converted to a
 *   string: `String([["https://x"]])` is `"https://x"`, so a conversion would
 *   name a target the client never sent as one.
 *
 * Only a JSON body can carry a malformed value: a form parses to a string or
 * an array of strings.
 */
export function readTargetParameter(value: unknown): readonly string[] | null {
	if (value === undefined || value === null || value === "") return [];
	if (typeof value === "string") return [value];
	if (Array.isArray(value) && value.every((entry) => typeof entry === "string")) {
		return (value as readonly string[]).filter((entry) => entry !== "");
	}
	return null;
}

/**
 * Extracts the `resource` parameter per RFC 8707 from a request's parameters —
 * a token request body, or the `/authorize` query or form — as
 * {@link readTargetParameter} reads it.
 *
 * Returns `null` when it names nothing (absent, null, `""`, or empty entries
 * only) and also when it is malformed: these callers read a malformed
 * `resource` as none requested. The token-exchange grant, which refuses a
 * malformed one with `invalid_target`, calls {@link readTargetParameter}.
 */
export function extractResourceParam(body: Record<string, unknown>): readonly string[] | null {
	const resources = readTargetParameter(body.resource);
	return resources !== null && resources.length > 0 ? resources : null;
}

/**
 * The audience to mint for when a `resource` was requested and no policy
 * narrowed one — RFC 8707 §2 read as "the AS derives the audience from the
 * request", rather than minting its default and then rejecting it.
 *
 * Returns `undefined` when derivation is not possible, leaving the caller's
 * existing fallback in place; {@link unrepresentedResources} then rejects the
 * request, so a non-derivable case still fails closed rather than silently
 * issuing a mismatched audience.
 *
 * Derivation is bounded by `allow` — the client's `allowedAudiences` plus its
 * own client id, the same ceiling a policy-returned audience is held to.
 * Without that bound, naming a resource would be enough to mint a token for
 * any audience, which is the opposite of what resource indicators are for.
 *
 * Two distinct resources are not derivable: `aud` is a single string. A
 * repeated identical resource collapses to that one audience.
 */
export function deriveAudienceFromResources(
	resources: readonly string[] | null | undefined,
	allow: ReadonlySet<string>,
): string | undefined {
	if (!resources || resources.length === 0) return undefined;
	const distinct = [...new Set(resources)];
	if (distinct.length !== 1) return undefined;
	const only = distinct[0];
	return only !== undefined && allow.has(only) ? only : undefined;
}

/**
 * Returns the requested resource indicators that the issued token's audience
 * does NOT represent. Empty result means the request is satisfiable.
 *
 * RFC 8707 §2 requires the access token's audience to be the resource
 * indicator(s) the client asked for; when the AS cannot bind the token to
 * them, the response is `invalid_target`. This helper is the shared decision
 * for that check across `client_credentials`, `refresh_token`,
 * `authorization_code`, jwt-bearer and `/authorize`, generalising the
 * enforcement the token-exchange grant has carried since v0.5.3 (IH-8).
 *
 * `generateToken` emits a SINGLE `aud`, so "represented" is string equality
 * against that one value. Two consequences worth stating, because both look
 * like helper decisions and are actually token-shape consequences:
 *
 * - Two distinct resources can never both be represented. The multi-resource
 *   case therefore rejects rather than issuing an array-valued `aud` or
 *   splitting into several tokens.
 * - A token with no audience represents nothing, so any resource request
 *   against it is unsatisfiable. Failing closed there avoids minting an
 *   audience-less token in response to an explicit targeting request.
 *
 * Duplicates that match the audience are not a widening — the client named one
 * target more than once — and are accepted.
 */
export function unrepresentedResources(
	resources: readonly string[] | null | undefined,
	audience: string | null | undefined,
): readonly string[] {
	if (!resources || resources.length === 0) return [];
	if (audience === null || audience === undefined) return [...resources];
	return resources.filter((resource) => resource !== audience);
}
