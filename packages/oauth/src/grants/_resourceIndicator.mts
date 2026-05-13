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
