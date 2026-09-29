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
 * RFC 8707 resource indicators: reading the `resource` parameter (and RFC
 * 8693's `audience`), deriving an audience from it, and checking that an
 * issued audience represents it. Pure functions, shared by grant packages
 * that do not depend on one another; the consumers are listed in
 * `docs/design-vocabulary.md`. See ADR 2026-07-31-rfc8707-resource-audience-binding.
 *
 * Values are never comma-split: RFC 8707 §5.4 treats each value as a URI, and
 * URIs may contain commas.
 */

/**
 * Reads a target parameter (RFC 8707 `resource` or RFC 8693 `audience`) as a
 * form or JSON body delivers it.
 *
 * - Absent, `null` or `""`: `[]` (RFC 6749 §3.2: a parameter without a value
 *   is treated as omitted).
 * - A string: that value, whole.
 * - An array of strings: its non-empty entries in order, so
 *   `resource=&resource=https://x` is not refused under an empty name.
 * - Anything else: `null`, malformed (RFC 8707 §2 `invalid_target`). Never
 *   stringified: `String([["https://x"]])` would name a target the client
 *   never sent. Only a JSON body can carry such a value.
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
 * The RFC 8707 `resource` of a token request body or `/authorize` query, read
 * by {@link readTargetParameter}. `null` when it names nothing or is
 * malformed: these callers treat a malformed `resource` as none requested.
 * Token exchange, which refuses it, calls {@link readTargetParameter} instead.
 */
export function extractResourceParam(body: Record<string, unknown>): readonly string[] | null {
	const resources = readTargetParameter(body.resource);
	return resources !== null && resources.length > 0 ? resources : null;
}

/**
 * The audience to mint for when a `resource` was requested and no policy
 * narrowed one (RFC 8707 §2: the AS derives the audience from the request).
 *
 * Bounded by `allow` (the client's `allowedAudiences` plus its client id, the
 * ceiling a policy audience is held to); unbounded, naming a resource would
 * mint a token for any audience. Two distinct resources are not derivable
 * because `aud` is a single string. `undefined` when not derivable: the
 * caller keeps its fallback and {@link unrepresentedResources} fails closed.
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
 * The requested resource indicators the issued audience does NOT represent.
 * Empty means satisfiable; otherwise the answer is `invalid_target` (RFC 8707
 * §2).
 *
 * `generateToken` emits a single `aud`, so "represented" is string equality
 * with it: two distinct resources never both pass, and a token with no
 * audience represents nothing (fails closed). Duplicates of the audience are
 * accepted.
 */
export function unrepresentedResources(
	resources: readonly string[] | null | undefined,
	audience: string | null | undefined,
): readonly string[] {
	if (!resources || resources.length === 0) return [];
	if (audience === null || audience === undefined) return [...resources];
	return resources.filter((resource) => resource !== audience);
}
