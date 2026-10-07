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
 * boot/index.mts — Internal barrel for the A2-β boot planner package.
 *
 * Re-exports the orchestrator (`createApp`) and the complete type surface
 * from `types.mts` (intermediate stage types, `AppHandle`, `BootError` class,
 * `BootErrorReason`, `BootStage`, all per-reason `*Details` interfaces,
 * and collector contracts).
 *
 * The package root `index.mts` selectively re-exports the subset of these
 * symbols that forms the public API. Phase 9 (A2-γ caller migration) deleted
 * the legacy v0.4.x `createApp` body and the `createBootApp` coexistence
 * alias; the package root's `createApp` now resolves to this orchestrator
 * directly via `./app.mjs`.
 *
 * Per A2-β §6.4 / §9.
 */
export { createApp } from "./create-app.mjs";
export { BootError } from "./types.mjs";
