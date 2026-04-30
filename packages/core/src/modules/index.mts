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
// v0.5.0 manifest exports — `Module` here is the v0.5.0 erased manifest type.
export * from "./manifest/index.mjs";

// PathResolver remains — it is the type for `bootstrapComponents.pathResolver`.
// FederationProviderHandle remains — it is the structural narrowing of the
// `federationProviders` synthetic key for core-adjacent route consumers
// (oauth/logout + oauth/federationToken). The legacy v0.4.x `LegacyModule` /
// `ModuleContext` types were deleted in Phase 9 (A2-γ caller migration).
export type { FederationProviderHandle, PathResolver } from "./types.mjs";
