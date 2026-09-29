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
 * ComponentMap: the typed DI graph for manifest authoring.
 *
 * The base interface is intentionally empty. Slots are added by declaration
 * merging, from this package and from downstream packages such as
 * @o3co/auth-provider-redis:
 *
 *     declare module "@o3co/auth-provider-core" {
 *       interface ComponentMap {
 *         readonly mySlot: MyType;
 *       }
 *     }
 *
 * Grep `declare module "@o3co/auth-provider-core"` for the slot list (`config`
 * and `pathResolver` are in `boot/types.mts`). Consumers MUST namespace their
 * own keys (e.g. `acme.cacheClient`) to avoid colliding with o3co slot names.
 */
// biome-ignore lint/suspicious/noEmptyInterface: declaration-merge target — the empty base IS the contract
export interface ComponentMap {}

/**
 * The union of all keys declared on ComponentMap (`never` for the empty base),
 * derived as packages declaration-merge slots.
 */
export type ComponentKey = keyof ComponentMap;
