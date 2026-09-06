/**
 * File-internal helper for extracting the RFC 8707 `resource` parameter from
 * a request body. Internal to grants/ — NOT exported from the package barrel.
 * The leading underscore signals file-internal status to sibling modules.
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