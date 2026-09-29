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
 * `resolverForTests`: the branded `SessionRequirementResolver` a test builds
 * when it constructs a consumer by hand. It is registered in the same set as
 * the boot planner's, so the brand stops accidents, not a deployment that
 * imports the testing entry on purpose. Each requirement is registered and
 * its reach sealed as boot does. `allowAnyReach` lifts the reach rules (the
 * snapshot stays) for tests of admission's own mechanics that need two
 * reaching requirements; nothing else uses it.
 */

import { sessionRequirementResolverOver } from "../admit.mjs";
import {
	type RegisteredRequirement,
	registeredRequirement,
	type SessionRequirement,
	type SessionRequirementResolver,
	sealRegisteredReach,
	snapshotReach,
} from "../requirement.mjs";

/** What a test that meets the one-reacher rule can do about it. */
const ALLOW_ANY_REACH_REMEDY = "pass allowAnyReach for a test of admission's own mechanics";

/**
 * The resolver a test hands a consumer: `requirements` by their names, in the
 * order given. Two of one name are refused, as boot refuses a duplicate
 * contribution. With `issuer`, each page is held to that origin. Each reach
 * is read once, here, held to boot's rules unless `allowAnyReach`, and the
 * resolver answers that snapshot.
 */
export function resolverForTests(
	requirements: readonly SessionRequirement[],
	options: { readonly issuer?: string; readonly allowAnyReach?: boolean } = {},
): SessionRequirementResolver {
	if (!Array.isArray(requirements)) {
		throw new RangeError("resolverForTests: requirements must be a list");
	}
	const byName = new Map<string, RegisteredRequirement>();
	for (const candidate of requirements) {
		// What is wrong is named by the registration itself, as boot reports it.
		const requirement = registeredRequirement(candidate, options.issuer);
		if (byName.has(requirement.name)) {
			throw new RangeError(`resolverForTests: two requirements are named "${requirement.name}"`);
		}
		byName.set(requirement.name, requirement);
		if (options.allowAnyReach === true) {
			snapshotReach(requirement);
			continue;
		}
		sealRegisteredReach(requirement, ALLOW_ANY_REACH_REMEDY);
	}
	return sessionRequirementResolverOver({
		get: (name) => byName.get(name),
		entries: () => byName.entries(),
	});
}
