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
 * Public test-helper surface for `@o3co/auth-provider-core`.
 *
 * Exposed via the `./testing` subpath in `package.json#exports`. Consumer
 * test code (sibling packages, downstream applications, OSS adopters) may
 * import from here; production runtime code MUST NOT — the symbols here
 * are intended for fixtures and integration tests only.
 *
 * A2-γ spec §6.1 + §7 prescribes this subpath; PR α (orthogonal
 * schema/default cleanup) lands the initial export surface (config-fixture
 * factories). `createTestApp` / `TestInspect` are added in this PR
 * (Phase 9 caller migration).
 *
 * Stability: identifiers exported here follow the same semver discipline
 * as the main `.` export — additions are minor, signature changes are
 * major.
 */

/**
 * Internal `GrantRegistry` class re-exported through the `./testing`
 * subpath for OAuth/integration tests that construct a registry directly
 * (rather than through `createApp` + module-based `contributes.grants`).
 *
 * The public re-export from `@o3co/auth-provider-core` (the package root)
 * was removed at v0.6.0 per AS-8 / A2-γ §3.3. Production code MUST NOT
 * import these symbols — wire grants on a module's `defineModule`
 * manifest and let the boot planner own the registry.
 *
 * This re-export exists solely so existing OAuth route tests that depend
 * on direct registry construction can continue to compile without a
 * mass-refactor to the module-based pattern. New tests SHOULD prefer the
 * `createApp` / module-based wiring.
 */
export { GrantRegistry, GrantRegistryError } from "../grants/registry.mjs";
export { createTestApp, type TestAppHandle } from "./create-test-app.mjs";
export {
	makeValidAppConfig,
	makeValidCoreConfig,
	makeValidFullSections,
} from "./fixtures/valid-config.mjs";
export type { TestInspect } from "./test-inspect.mjs";
