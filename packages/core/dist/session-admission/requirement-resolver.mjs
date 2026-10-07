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
/** The resolvers the boot planner and `resolverForTests` built. */
const knownResolvers = new WeakSet();
/**
 * Builds the branded resolver over `source` and records it, so `admitSession`
 * knows it. `wrap` is the planner's read gate (closed while the `provides`
 * factories run); it is applied to the object recorded, which is the one a
 * consumer is handed. For the boot planner and `resolverForTests` alone.
 * @internal
 */
export function sessionRequirementResolverOver(source, wrap = (view) => view) {
    const view = wrap(Object.freeze({
        get: (name) => source.get(name),
        entries: () => source.entries(),
        action: (name) => source.action(name),
    }));
    knownResolvers.add(view);
    return view;
}
const isKnownResolver = (value) => typeof value === "object" && value !== null && knownResolvers.has(value);
/**
 * Refuses a resolver the planner or `resolverForTests` did not build; a
 * home-made object or a copy forges nothing. Consumer factories run it on
 * their `requirements` at construction, with their own name as `factory` and
 * the names of the actions they admit as `admits`, so a missing or forged
 * resolver, or an admitted action no module registers, fails where the
 * composition is assembled rather than on a request. Admission also runs it
 * on every call.
 */
export function checkResolver(value, factory, admits = []) {
    const who = factory === undefined ? "" : `${factory}: `;
    if (isKnownResolver(value)) {
        for (const name of admits) {
            if (value.action(name) === undefined) {
                throw new RangeError(`${who}admits ${JSON.stringify(name)}, which no module registers: the module that installs it registers it under contributes.admissionActions`);
            }
        }
        return value;
    }
    if (value === undefined || value === null) {
        throw new RangeError(`${who}requirements is required — the sessionRequirementResolver the boot planner built (the manifests pass it), or resolverForTests from @o3co/auth-provider-core/testing in a test`);
    }
    throw new RangeError(`${who}requirements must be the sessionRequirementResolver the boot planner built (or resolverForTests, in a test)`);
}
