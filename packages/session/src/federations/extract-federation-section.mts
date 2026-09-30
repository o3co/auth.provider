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
 * Extract and normalize one federation's config slice, so every per-federation
 * module shares the same shape rules (README, "Configuring federations"):
 *
 * - Flat (default): `{ enabled, type?, ...credentials }`; `type` defaults to
 *   `<name>`.
 * - Nested: `{ enabled, type, [type]: { ...credentials } }`; other top-level
 *   fields pass through onto the merged result.
 * - Mixed (a top-level credential field beside a nested sub-section) is
 *   ambiguous and throws.
 *
 * Returns `undefined` when the section is missing or `enabled` is not `true`,
 * otherwise the normalized credential object with `type` always set.
 */
export function extractFederationSection(
	federations: Readonly<Record<string, unknown>>,
	name: string,
): { type: string; [key: string]: unknown } | undefined {
	const raw = federations[name];
	if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;

	const section = raw as Record<string, unknown>;
	if (section.enabled !== true) return undefined;

	const type = typeof section.type === "string" ? section.type : name;
	const subSection = section[type];
	const isNested =
		subSection != null && typeof subSection === "object" && !Array.isArray(subSection);

	if (isNested) {
		// Reject mixed shape: nested sub-section + top-level credential fields.
		const flatCredentialFields = ["clientId", "clientSecret", "callbackURL"].filter(
			(k) => k in section,
		);
		if (flatCredentialFields.length > 0) {
			throw new Error(
				`core.federations.${name}: mixed shape — remove top-level ${flatCredentialFields.join("/")} OR the ${type} { ... } sub-section`,
			);
		}

		// Merge: sub-section credentials overlaid on top-level passthrough fields.
		// Strip control keys (enabled / type / [type]) from the top-level slice
		// so they do not appear twice or shadow sub-section fields.
		const { enabled: _enabled, type: _type, [type]: _sub, ...topLevel } = section;
		return { type, ...topLevel, ...(subSection as Record<string, unknown>) };
	}

	// Flat shape: strip control keys and return credentials at top level.
	const { enabled: _enabled, type: _type, ...credentials } = section;
	return { type, ...credentials };
}
