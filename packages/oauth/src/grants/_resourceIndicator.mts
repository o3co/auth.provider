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
 * File-internal helper for extracting the RFC 8707 `resource` parameter from
 * a request body. Internal to grants/ — NOT exported from the package barrel.
 * The leading underscore signals file-internal status to sibling modules.
 *
 * No comma-splitting is performed: RFC 8707 §5.4 treats each `resource`
 * value as a URI and URIs may legally contain commas, so splitting would
 * silently corrupt valid resource indicators.
 */

/**
 * Extracts the `resource` parameter from a token request body per RFC 8707.
 *
 * Returns `null` when the parameter is absent, null, or an empty string.
 * A single string is normalised to a one-element array. An array is returned
 * as-is only when every element is a string; otherwise returns `null`
 * (defensive against malformed / injected input).
 */
export function extractResourceParam(body: Record<string, unknown>): readonly string[] | null {
	const v = body.resource;
	if (v === undefined || v === null || v === "") return null;
	if (typeof v === "string") return [v];
	if (Array.isArray(v) && v.every((x) => typeof x === "string")) return v as readonly string[];
	return null;
}

/**
 * Returns the requested resource indicators that the issued token's audience
 * does NOT represent. Empty result means the request is satisfiable.
 *
 * RFC 8707 §2 requires the access token's audience to be the resource
 * indicator(s) the client asked for; when the AS cannot bind the token to
 * them, the response is `invalid_target`. This helper is the shared decision
 * for that check across `client_credentials`, `refresh_token`, and
 * `authorization_code`, generalising the enforcement the token-exchange grant
 * has carried since v0.5.3 (IH-8).
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
