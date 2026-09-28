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
 * `resolverForTests` (the session-admission ADR's D1): the branded
 * `SessionRequirementResolver` a test builds when it constructs a consumer
 * by hand, registered in the same set the boot planner's resolvers are — so
 * the brand stops accidents, not a deployment that imports the testing
 * entry on purpose. Each requirement is registered as boot registers one
 * (`registeredRequirement`): its shape held to the contract, its page on the
 * issuer's origin when one is given, and what the resolver answers a copy.
 */

import { sessionRequirementResolverOver } from "../admit.mjs";
import {
	registeredRequirement,
	type SessionRequirement,
	type SessionRequirementResolver,
} from "../requirement.mjs";

/**
 * The resolver a test hands a consumer: `requirements` by their names, in the
 * order given. Two of one name are refused, as boot refuses a duplicate
 * contribution. With `issuer`, each page is held to that origin.
 */
export function resolverForTests(
	requirements: readonly SessionRequirement[],
	options: { readonly issuer?: string } = {},
): SessionRequirementResolver {
	if (!Array.isArray(requirements)) {
		throw new RangeError("resolverForTests: requirements must be a list");
	}
	const byName = new Map<string, SessionRequirement>();
	for (const candidate of requirements) {
		// What is wrong is named by the registration itself, as boot reports it.
		const requirement = registeredRequirement(candidate, options.issuer);
		if (byName.has(requirement.name)) {
			throw new RangeError(`resolverForTests: two requirements are named "${requirement.name}"`);
		}
		byName.set(requirement.name, requirement);
	}
	return sessionRequirementResolverOver({
		get: (name) => byName.get(name),
		entries: () => byName.entries(),
	});
}
