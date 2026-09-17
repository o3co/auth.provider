/**
 * `parseAccessTokenHeader` moved to core in #324 so
 * `protectedResourceBindingMw` could share it instead of re-parsing the
 * header inline with its own duplicate scheme set. Re-exported here for
 * import-path compatibility within this package.
 */
export { parseAccessTokenHeader } from "@o3co/auth-provider-core";
//# sourceMappingURL=accessTokenHeader.d.mts.map