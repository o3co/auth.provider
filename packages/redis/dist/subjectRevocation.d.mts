import type { AdapterBuilder, SubjectRevocation } from "@o3co/auth-provider-core";
import type { SubjectRevocationClient } from "./clients.mjs";
/**
 * Redis {@link SubjectRevocation} (#321) — the per-subject not-before
 * watermark, shared across replicas.
 *
 * ## Why the write is not a `SET`
 *
 * The value is one number and the shape looks like `SET key value PX ttl`. It
 * is not, because the watermark is **monotonic**: two credential changes in
 * quick succession, the second computed on a replica whose clock is behind,
 * must not move the line backwards and resurrect every token the first one
 * killed. Last-writer-wins does exactly that. A client-side
 * read-compare-write loses the same race one round-trip later, with two
 * replicas interleaving between the `GET` and the `SET`.
 *
 * So the comparison happens on the server, in one command
 * (`setWatermarkMonotonic`), and the same guard covers the entry's own expiry:
 * shortening an in-force watermark would retire the line while tokens it must
 * refuse are still presentable.
 *
 * An **expired** key is an absent key, so the guard does not resurrect a
 * lapsed watermark's larger value — a reset arriving after the previous
 * watermark timed out starts from its own value, matching the in-process
 * adapter.
 *
 * ## TTL sizing is the caller's contract, not this adapter's
 *
 * `expiresAt` must reach as far as the longest-lived credential the watermark
 * has to refuse — the refresh token, not the access token, wherever the
 * composition forwards `subjectRevocation` to the refresh grant. See
 * `SubjectRevocation` in core for why. This adapter stores what it is given.
 */
export interface RedisSubjectRevocationOptions {
    readonly client: SubjectRevocationClient;
    /** Defaults to the bundle's production layout, `ss:rev:`. */
    readonly keyPrefix?: string;
}
export declare function createRedisSubjectRevocation(deps: RedisSubjectRevocationOptions): SubjectRevocation;
/**
 * AdapterFactory builder for the Redis-backed `SubjectRevocation` (#321).
 *
 * Use when per-adapter `AdapterFactory` granularity is needed; for the common
 * case the bundled `redisSessionStoresModule` is sufficient. Default
 * `keyPrefix` matches the bundle's production layout (`ss:rev:`) so swapping
 * between bundle and individual builder does not change the keyspace.
 *
 * Missing `client` throws at boot rather than crashing at the first Redis op,
 * matching every other builder in this package.
 */
export declare const redisSubjectRevocationBuilder: AdapterBuilder<SubjectRevocation>;
//# sourceMappingURL=subjectRevocation.d.mts.map