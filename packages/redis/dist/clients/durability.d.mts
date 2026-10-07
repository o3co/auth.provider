/**
 * What a Redis server says about keeping what it is written — read at boot
 * when a store whose keys must outlive memory pressure and a restart is built.
 * Each part is `undefined` when it could not be read: the server refused the
 * question (`refusal`), or answered without the value.
 */
export interface RedisDurability {
    /** `INFO memory`'s `maxmemory_policy`, or `CONFIG GET maxmemory-policy` where INFO does not say. */
    readonly maxmemoryPolicy: string | undefined;
    /** `INFO persistence`'s `aof_enabled`. */
    readonly appendOnly: boolean | undefined;
    /** `CONFIG GET save` is not empty: RDB snapshots are taken. Asked only when AOF is off. */
    readonly snapshots: boolean | undefined;
    /** The first reply that refused a question — an unknown or renamed command, `NOPERM`, a disabled command — as the driver raised it. Logged by its projection only. */
    readonly refusal: unknown;
    /**
     * The operator's assertion that the server runs `maxmemory-policy noeviction`, for a server
     * that will not say. The stores' eviction gate reads it only while `maxmemoryPolicy` is
     * unread: a policy the server reports always decides.
     */
    readonly assumeNoEviction?: boolean;
}
//# sourceMappingURL=durability.d.mts.map