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
export { createTestApp, type TestAppHandle } from "./create-test-app.mjs";
export { makeValidAppConfig, makeValidCoreConfig, makeValidFullSections, } from "./fixtures/valid-config.mjs";
export type { TestInspect } from "./test-inspect.mjs";
//# sourceMappingURL=index.d.mts.map