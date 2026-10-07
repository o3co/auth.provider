/**
 * The refresh-token family store's client: a WATCH/MULTI/EXEC compare-and-set, on a connection
 * of its own that `duplicate()` opens and disposal closes.
 */
import type { RedisDurability } from "./durability.mjs";
/**
 * Chainable transaction pipeline returned by `RefreshTokenFamilyClient.multi()`.
 */
export interface RefreshTokenFamilyMultiClient {
    set(key: string, value: string, mode: "PX", ttlMs: number): RefreshTokenFamilyMultiClient;
    /**
     * Execute the queued commands. MUST reject when any queued command failed
     * (a driver that reports per-command errors inside the reply, as ioredis
     * does, is adapted here); `null` is the WATCH-abort signal, which the CAS
     * loop reads as "conflict, retry".
     */
    exec(): Promise<unknown[] | null>;
}
/**
 * Backing client for RefreshTokenFamilyStore adapters. The `duplicate()` method
 * returns a `DisposableRefreshTokenFamilyClient` bound to a new underlying
 * connection, required for WATCH/MULTI/EXEC CAS isolation. That connection is
 * never replaced: once it is lost, every later command on the duplicate
 * rejects, since a command carried to a new connection runs without the
 * `WATCH`.
 */
export interface RefreshTokenFamilyClient {
    set(key: string, value: string, mode: "PX", ttlMs: number, condition: "NX"): Promise<"OK" | null>;
    get(key: string): Promise<string | null>;
    pttl(key: string): Promise<number>;
    watch(...keys: string[]): Promise<"OK">;
    unwatch(): Promise<"OK">;
    multi(): RefreshTokenFamilyMultiClient;
    duplicate(): DisposableRefreshTokenFamilyClient;
    /**
     * What the server says about keeping what it is written, read once by the
     * store's factory for its eviction gate: a revoked family evicted before its
     * expiry reads as not revoked.
     */
    durability(): Promise<RedisDurability>;
}
/**
 * A `RefreshTokenFamilyClient` that owns a single network connection and is
 * responsible for closing it. Returned by `RefreshTokenFamilyClient.duplicate()`
 * so consumer code can use `await using conn = client.duplicate()` for scoped,
 * exception-safe connection lifetime.
 */
export interface DisposableRefreshTokenFamilyClient extends RefreshTokenFamilyClient, AsyncDisposable {
    [Symbol.asyncDispose](): Promise<void>;
}
//# sourceMappingURL=refresh-token-family.d.mts.map