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
 * factories). The `createTestApp` / `TestInspect` helpers prescribed by
 * §7.2 will be added in a later PR (Phase 9 caller migration).
 *
 * Stability: identifiers exported here follow the same semver discipline
 * as the main `.` export — additions are minor, signature changes are
 * major.
 */

export {
	makeValidAppConfig,
	makeValidCoreConfig,
	makeValidFullSections,
} from "./fixtures/valid-config.mjs";
