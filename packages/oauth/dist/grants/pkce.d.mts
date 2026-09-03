import type { Logger } from "@o3co/auth-provider-core";
/**
 * Resolves the PKCE supported methods from an untyped pkce config block.
 *
 * Replaces the duplicated `Array.isArray(...) ? (... as string[])` pattern
 * at `authorization.mts` and `routes.mts`: `Array.isArray` proves the value
 * is an array but does NOT constrain element types, so a misconfiguration
 * such as `supportedMethods = [123, null, "S256"]` would have been accepted
 * as `string[]` and silently weakened the PKCE method allowlist (the
 * `.includes(method)` gate in consumers happens to filter the non-string
 * elements by accident, not by contract).
 *
 * Behaviour:
 * - Non-array / undefined / missing field → fall back to `["S256", "plain"]`.
 * - Array with mixed string/non-string elements → filter to strings and warn.
 * - Array filtered to empty (or literal `[]`) → fall back to default
 *   (defensive: an empty allowlist would disable PKCE entirely).
 *
 * The `logger` argument is optional. As of F6 PR4 (v0.5.1) both production
 * call sites (`authorization.mts` via `GrantDependencies.logger`, and
 * `routes.mts` via `createOAuthRouter` options) DO supply a logger so the
 * misconfig warnings reach operators' structured logging stack. Tests
 * continue to call without a logger to exercise the optional-logger path.
 *
 * Per TS-4 spec (Wave 5j) + Codex calibration delta 2 (literal-empty +
 * filtered-empty cases tested separately).
 */
export declare function resolvePkceSupportedMethods(pkceConfig: Record<string, unknown> | undefined, logger?: Logger): readonly string[];
//# sourceMappingURL=pkce.d.mts.map