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
 * The set of synthetic ComponentMap keys at v0.5.0. The boot planner
 * (Phase 4 / A2-β §5.1 step 3) consults this set to reject:
 * - any module's `provides[K]` where `K ∈ SYNTHETIC_COMPONENT_KEYS`
 * - any `bootstrapComponents[K]`
 * - any `overrideComponents[K]`
 *
 * A5 (Phase 7) added `federationRedirectPolicyResolver` — the synthetic
 * projection for `federationRedirectPolicies` contributions (typed in
 * `@o3co/auth-provider-session/src/federations/contributes.mts`).
 *
 * Per A2-α §6.5 NORMATIVE constraints. The PRIMARY immutability guard
 * is the TypeScript declared type `ReadonlySet<string>` — `.add()`,
 * `.delete()`, and `.clear()` are prevented at compile time. The
 * runtime `Object.freeze` call additionally marks the Set object as
 * frozen (no new own properties, no prototype change), but it does
 * NOT prevent the built-in Set methods from mutating the internal
 * `[[SetData]]` slot — that is a JavaScript engine constraint specific
 * to built-in collection types. A consumer casting `(s as Set<string>)`
 * to mutate is explicitly bypassing the public type contract.
 */
export const SYNTHETIC_COMPONENT_KEYS = Object.freeze(new Set([
    "federationProviders",
    "tokenExchangeValidatorResolver",
    "grantHandlerResolver",
    "federationRedirectPolicyResolver",
]));
