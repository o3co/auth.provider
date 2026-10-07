/**
 * A TCP server standing in for Redis: it records what each connection sends,
 * and answers as a server running `noeviction` does — `HELLO` refused, so the
 * client speaks RESP2, `INFO` with the policy, anything else `OK` — so a
 * client dialled at it writes its handshake and the stores whose factories
 * read the policy build.
 */
export declare function listeningRedis(): Promise<{
    readonly port: number;
    readonly received: () => string;
    readonly close: () => Promise<void>;
}>;
//# sourceMappingURL=redis-stand-in.fixture.d.mts.map