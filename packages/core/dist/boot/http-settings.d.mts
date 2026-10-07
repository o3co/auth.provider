/**
 * Why `config`'s top-level `cors` section refuses boot, or `undefined` when
 * a loaded module's section is `cors` (`owned`, the top-level sections
 * something loaded owns), which reads it, or when it sets nothing: absent,
 * an own `undefined` (as the relocation refusal reads it), or a value
 * `pathsSetBy` finds nothing in (`{}`, or only empty sections). Core reads
 * its CORS origins from the `httpSettings` slot alone, so any other `cors`
 * is read by nothing; a loaded module that relocates `cors` refuses it
 * first, before parse, naming its own path. A section whose read throws
 * refuses the same way. Names the section, never a value.
 */
export declare function unreadCorsSection(config: unknown, owned: ReadonlySet<string>): string | undefined;
/**
 * The slot's `cors.allowedOrigins`, read once, each entry held to
 * `checkSerializedOrigin` (the rule the module's schema holds its section's to),
 * answered as a frozen copy.
 *
 * @throws RangeError naming the member (and the index) that does not hold,
 *   or the slot when it holds no settings object.
 */
export declare function httpSettingsCorsOrigins(value: unknown): readonly string[];
//# sourceMappingURL=http-settings.d.mts.map