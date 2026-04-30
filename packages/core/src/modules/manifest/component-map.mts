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
 * ComponentMap — the typed DI graph for v0.5.0 manifest authoring.
 *
 * The base interface is intentionally empty. Slot declarations are added by
 * other files in @o3co/auth-provider-core (and by downstream packages such
 * as @o3co/auth-provider-redis) via TypeScript declaration merging:
 *
 *     declare module "@o3co/auth-provider-core" {
 *       interface ComponentMap {
 *         readonly mySlot: MyType;
 *       }
 *     }
 *
 * Per A2-α §6.1 the v0.5.0 baseline slot set is added incrementally during
 * Phases 3–8 of the v0.5.0 redesign. This empty base is the foundation.
 *
 * Per the cross-spec X1 amendment (documented in v0.5.0 redesign specs A3
 * §5.5 line 391 and A4 §5.6 of this repository's design history): the
 * v0.5.0 ComponentMap
 * does NOT contain the legacy `userSessionStore: UserSessionStoreBase` nor
 * `refreshTokenStore: RefreshTokenStoreBase` slots. Phase 5 (A1) and later
 * phases declaration-merge their replacement slots without those legacy
 * names appearing.
 *
 * Consumer-side augmentation MUST namespace consumer-specific keys (e.g.
 * `acme.cacheClient`) to avoid colliding with o3co-claimed slot names.
 *
 * v0.5.0 in-tree slot inventory (declaration-merged into this interface
 * from elsewhere in the package; grep `declare module "@o3co/auth-provider-core"`
 * for the authoritative list):
 *
 * - `config: AppConfig` — declared in `boot/types.mts` per A2-β §6.2
 * - `pathResolver: PathResolver` — declared in `boot/types.mts` per A2-β §6.2
 * - (Phase 5 onward adds storage / federation / session slots)
 */
// biome-ignore lint/suspicious/noEmptyInterface: declaration-merge target — the empty base IS the contract
export interface ComponentMap {}

/**
 * The set of all keys declared on ComponentMap.
 *
 * In an empty base, this is `never`. As packages declaration-merge slots,
 * the type expands to the union of all declared keys. Consumers do NOT
 * write `ComponentKey = "config" | "keyStore" | ...` directly — they let
 * the type system derive it from `keyof ComponentMap`.
 */
export type ComponentKey = keyof ComponentMap;
