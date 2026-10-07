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
 * Pure utility for extracting and normalizing a single federation's config slice.
 *
 * Per A2-γ §3.5 — migrated from the v0.4.x `sessionModule.init()` body so that
 * per-federation `defineModule` consumers can share the same flat / nested shape
 * normalization without re-implementing it. The shape rules are:
 *
 *   FLAT shape (default):
 *     federations.<name> = { enabled, type?, ...credentials }
 *     The credentials are at the top level. `type` defaults to `<name>` when
 *     omitted (shorthand: key serves as type identifier).
 *
 *   NESTED shape (explicit, for multi-tenant or custom-typed federations):
 *     federations.<name> = { enabled, type, [type]: { ...credentials } }
 *     The sub-section keyed by `type` carries the credentials; top-level
 *     non-control fields are passthrough (preserved on the merged result).
 *
 *   MIXED shape (rejected):
 *     federations.<name> = { enabled, type, clientId: "x", [type]: {...} }
 *     Top-level credential fields AND a nested sub-section is ambiguous —
 *     throws so consumers must pick one shape per entry.
 *
 * Returns `undefined` when the section is missing or `enabled` is not `true`.
 * Returns the normalized credential object otherwise (with `type` always set).
 */
export function extractFederationSection(
	federations: Record<string, unknown>,
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
				`federations.${name}: mixed shape — remove top-level ${flatCredentialFields.join("/")} OR the ${type} { ... } sub-section`,
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
