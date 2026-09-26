/**
 * Loads the Redis session store's two libraries, `redis` and `connect-redis`,
 * which are optional peer dependencies of this package: nothing imports them
 * until the Redis store is built, so a deployment on the memory store need not
 * install them. When one is not installed, the load fails with a message that
 * names it and the install command, rather than with the resolver's bare
 * "Cannot find package". Internal to the package; `factory.mts` is its caller.
 */
/** What the Redis store builder uses from the two libraries. */
export type RedisStoreLibraries = {
    readonly createClient: typeof import("redis").createClient;
    readonly RedisStore: typeof import("connect-redis").RedisStore;
};
/** How each library is loaded: `import()` of its package name. */
export interface RedisStoreLibraryImports {
    readonly redis: () => Promise<Pick<typeof import("redis"), "createClient">>;
    readonly connectRedis: () => Promise<Pick<typeof import("connect-redis"), "RedisStore">>;
}
/**
 * Load `redis` and `connect-redis`, or fail without losing a failure:
 *
 * - A library that is not installed is named, in one message for both —
 *   rather than the resolver's bare "Cannot find package", which says neither
 *   that the package is an optional peer of this one nor which setting asked
 *   for it. The resolver's error is the cause.
 * - When the other library failed for a different reason, the message says so
 *   and that failure is the cause instead: the message already names what is
 *   missing, and the other failure is what it cannot restate.
 * - A single failure of any other kind is rethrown unchanged; two are thrown
 *   together as an `AggregateError` whose message is fixed text naming both
 *   packages. The failures themselves are its `errors`, whole, and a log line
 *   gets them where core's loggableError projects the members: their text is
 *   never copied into the message, where it would travel on as a plain string
 *   past every projection.
 *
 * What a message is for comes first: the names and the install command, then
 * the explanation. createApp prefixes the route factory's error with
 * `Module "sessionStoreModule" route factory failed: `, and a log line keeps
 * 256 characters of a message (core's LOGGED_STRING_MAX_LENGTH); the install
 * command and what failed are inside them for every combination
 * (`redisStoreLibraries.test.mts`).
 *
 * @param imports — how each library is loaded; the default imports it.
 */
export declare function loadRedisStoreLibraries(imports?: RedisStoreLibraryImports): Promise<RedisStoreLibraries>;
//# sourceMappingURL=redisStoreLibraries.d.mts.map