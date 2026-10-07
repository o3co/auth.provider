/**
 * Pure utility for extracting and normalizing a single federation's config slice.
 *
 * Per A2-γ §3.5 — migrated from the v0.4.x `sessionModule.init()` body so that
 * per-federation `defineModule` consumers can share the same flat / nested shape
 * normalization without re-implementing it. The shape rules are:
 *
 *   FLAT shape (default):
 *     federations.<name> = { enabled, type?, ...credentials }
 *     The credentials are at the top level. `type` defaults to `<name>` when
 *     omitted (shorthand: key serves as type identifier).
 *
 *   NESTED shape (explicit, for multi-tenant or custom-typed federations):
 *     federations.<name> = { enabled, type, [type]: { ...credentials } }
 *     The sub-section keyed by `type` carries the credentials; top-level
 *     non-control fields are passthrough (preserved on the merged result).
 *
 *   MIXED shape (rejected):
 *     federations.<name> = { enabled, type, clientId: "x", [type]: {...} }
 *     Top-level credential fields AND a nested sub-section is ambiguous —
 *     throws so consumers must pick one shape per entry.
 *
 * Returns `undefined` when the section is missing or `enabled` is not `true`.
 * Returns the normalized credential object otherwise (with `type` always set).
 */
export declare function extractFederationSection(federations: Record<string, unknown>, name: string): {
    type: string;
    [key: string]: unknown;
} | undefined;
//# sourceMappingURL=extract-federation-section.d.mts.map