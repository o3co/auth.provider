/**
 * Decide whether `cpSync` should copy a given source path.
 *
 * Only segments INSIDE `templateRoot` are checked against EXCLUDED_DIRS — the
 * install-prefix path above the root (e.g. `~/.npm/_npx/<hash>/node_modules/...`
 * when the package is run via `npx`) is ignored. Otherwise the filter would
 * reject every file whenever the package itself happens to live under a
 * `node_modules` directory (which is the v0.5.0 npx regression this fixes).
 *
 * The `pathSep` parameter exists so unit tests can exercise both POSIX and
 * Windows separators regardless of the host platform; production callers omit
 * it and pick up `path.sep` of the running platform. DO NOT change this to a
 * hardcoded `"/"` — `cpSync` passes back-slash-delimited absolute paths on
 * Windows, so segment splitting must follow the platform separator.
 */
export declare const shouldCopyTemplateEntry: (source: string, templateRoot: string, pathSep?: string) => boolean;
//# sourceMappingURL=template-filter.d.mts.map