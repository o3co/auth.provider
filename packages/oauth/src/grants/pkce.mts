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

import type { Logger } from "@o3co/auth-provider-core";

const DEFAULT_PKCE_METHODS: readonly string[] = Object.freeze(["S256", "plain"]);

/**
 * Resolves the PKCE supported methods from an untyped pkce config block.
 *
 * Replaces the duplicated `Array.isArray(...) ? (... as string[])` pattern
 * at `authorization.mts` and `routes.mts`: `Array.isArray` proves the value
 * is an array but does NOT constrain element types, so a misconfiguration
 * such as `supportedMethods = [123, null, "S256"]` would have been accepted
 * as `string[]` and silently weakened the PKCE method allowlist (the
 * `.includes(method)` gate in consumers happens to filter the non-string
 * elements by accident, not by contract).
 *
 * Behaviour:
 * - Non-array / undefined / missing field → fall back to `["S256", "plain"]`.
 * - Array with mixed string/non-string elements → filter to strings and warn.
 * - Array filtered to empty (or literal `[]`) → fall back to default
 *   (defensive: an empty allowlist would disable PKCE entirely).
 *
 * The `logger` argument is optional. v0.5.1 consumers (`authorization.mts`,
 * `routes.mts`) call without a logger because there is no logger slot on
 * `GrantDependencies` / `createOAuthRouter` deps in this release; the warn
 * branch is exercised via direct unit tests on the helper. Logger plumbing
 * to the call sites is deferred to D-4 (ComponentMap.logger wiring).
 *
 * Per TS-4 spec (Wave 5j) + Codex calibration delta 1 (no logger at consumer
 * sites in v0.5.1) + delta 2 (literal-empty + filtered-empty cases tested
 * separately).
 */
export function resolvePkceSupportedMethods(
	pkceConfig: Record<string, unknown> | undefined,
	logger?: Logger,
): readonly string[] {
	const raw = pkceConfig?.supportedMethods;
	if (!Array.isArray(raw)) return DEFAULT_PKCE_METHODS;
	const filtered = raw.filter((m): m is string => typeof m === "string");
	if (filtered.length === 0) {
		// All-non-string fallback (e.g. operator wrote `[123, null]`).
		// Pre-Claude-review-fixup the helper fell back to defaults silently
		// here, so a completely garbage allowlist disabled the operator's
		// intended PKCE policy with zero log signal. Warn now so the
		// misconfiguration is visible. We deliberately do NOT warn on the
		// `raw.length === 0` case (operator literal `[]` may be an
		// intentional "use defaults" signal); only an explicit non-empty
		// non-string array trips this branch.
		// Object-first per F5 D-4 Logger convention.
		if (raw.length > 0) {
			logger?.warn(
				{
					raw,
					removed: raw.length,
				},
				"pkce_supportedMethods_all_non_string_fallback_to_default",
			);
		}
		return DEFAULT_PKCE_METHODS;
	}
	if (filtered.length !== raw.length) {
		// Object-first call shape per F5 D-4 Logger convention: structured
		// fields first so PII-redaction tooling can inspect keys directly.
		logger?.warn(
			{
				raw,
				filtered,
				removed: raw.length - filtered.length,
			},
			"pkce_supportedMethods_non_string_filtered",
		);
	}
	return filtered;
}
