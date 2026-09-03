/**
 * File-internal helper for extracting the RFC 8707 `resource` parameter from
 * a grant request body. Internal to the webauthn grant — NOT exported from
 * the package barrel.
 *
 * Duplicated from packages/oauth/src/grants/_resourceIndicator.mts because
 * the webauthn package does not depend on @o3co/auth-provider-oauth and that
 * file is explicitly NOT barrel-exported (file-internal to oauth/grants/).
 * The helper is 5 lines of pure logic; the duplication cost is lower than
 * introducing a cross-package private import.
 *
 * Wave 2 consolidation candidate: move into @o3co/auth-provider-core so both
 * oauth and webauthn packages can share without private imports (issue #173).
 *
 * No comma-splitting is performed: RFC 8707 §5.4 treats each `resource`
 * value as a URI and URIs may legally contain commas, so splitting would
 * silently corrupt valid resource indicators.
 */
/**
 * Extracts the `resource` parameter from a token request body per RFC 8707.
 *
 * Returns `null` when the parameter is absent, null, or an empty string.
 * A single string is normalised to a one-element array. An array is returned
 * as-is only when every element is a string; otherwise returns `null`
 * (defensive against malformed / injected input).
 */
export declare function extractResourceParam(body: Record<string, unknown>): readonly string[] | null;
//# sourceMappingURL=_resourceIndicator.d.mts.map