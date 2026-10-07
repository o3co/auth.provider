/**
 * Redis {@link MfaFactorStore}: enrolled second factors, one hash per subject.
 *
 * ```text
 * <keyPrefix>{<subject>}   HASH   field <factor id> → the record
 *                                 field ~g          → the set's generation
 * ```
 *
 * `<subject>` and `<factor id>` are base64url of their JSON
 * (`internal/mfa-keys.mts`); `~` is not base64url, so no factor's field is
 * `~g`. Every operation touches the subject's one key, so a Cluster spreads
 * subjects across its slots. A hash holding a factor carries no TTL: an
 * enrolled factor does not expire. An emptied set's tombstone and a write's
 * replay key do carry one, so the factory holds the server to `noeviction`
 * (`internal/eviction-policy.mts`).
 *
 * A record is `<version>\n<fixed>\n<mutable>`: the version as decimal text,
 * one JSON line for what never changes after `createIf` (id, subject, kind,
 * binding, createdAt) and one for what `update` replaces (data, label,
 * lastUsedAt), so the compare-and-set is one script that never decodes the
 * JSON (`MfaFactorStoreClient`). `data` arrives sealed by the coordinator and
 * is kept byte for byte.
 *
 * A stored value that does not read back as the record written under that
 * subject and field is refused with an error quoting nothing it read: an
 * outage, never "no factor". Only a subject with no record that may count
 * opens a first binding, so a record read as absent would downgrade the
 * account.
 * See the MFA ADR (2026-09-25-multi-factor-authentication), D7 and D12.
 *
 * The factor set's generation follows core's conditional-write convention
 * (docs/adapter-surface.md, "Conditional writes"):
 *
 * - Each generation is minted here with `newStoreGeneration` and handed to
 *   the script that writes it. Each membership write keeps its answer under
 *   a replay key of its own (`<key>:w:<generation>`) until the declared clock
 *   skew past its deadline, so a copy the driver sends again answers the
 *   first copy's answer and writes nothing: no generation is issued twice
 *   (rule 8), and no write that landed answers `conflict` (rule 4).
 *   `listVersioned`, `createIf`, `removeIf` and `removeAllForSubject` are
 *   one script each (rules 1 and 2); `update` keeps `~g`.
 * - Every one of those scripts may write, so a read-only replica
 *   (`replica-read-only yes`, Redis's default) refuses it: the versioned read
 *   is answered by the primary, never such a replica (rule 2). `removeIf`,
 *   the reset and `listVersioned` declare `allow-oom`, so a full
 *   `noeviction` server still runs them; `createIf` is refused there.
 * - A write that leaves the hash holding `~g` alone keeps it as the set's
 *   tombstone for `BUNDLED_STORE_WRITE_LIFETIME_MS`, 24 hours, from that
 *   write, a reset of an already empty set included; a write that leaves a
 *   factor in it takes the expiry off (rule 6).
 * - A hash with factors and no `~g`, from a build before the set had a
 *   generation, answers `conflict` to every conditional write, and its first
 *   `listVersioned` gives it one (rule 8).
 * - Each membership write carries a deadline set at issue, `Date.now()` plus
 *   {@link WRITE_TIMEOUT_MS}, which its script compares with the server's
 *   clock before it reads or writes anything: at or past it, that copy writes
 *   nothing and the write rejects with its outcome unknown, since another
 *   copy may have committed, or may still commit within W (a server whose
 *   clock lags by the skew may judge another copy on time after a
 *   failover). The wait ends at the same timeout. So the write
 *   lifetime W is {@link REDIS_MFA_FACTOR_STORE_WRITE_LIFETIME_MS} (rule 6).
 *   Half 2 of the bound holds while the app's and Redis's clocks agree within
 *   the declared skew. A late command, whether resent, queued or stalled,
 *   writes nothing. The check bounds when a script starts: the server is
 *   assumed not to stall inside a running script, between its clock check
 *   and its write, for the whole of W.
 * - This store assumes acknowledged writes are not rolled back (persistence
 *   plus a failover setup that keeps acked writes); a deployment that accepts
 *   acked-write loss on failover also accepts that a conditional write may
 *   see a restored older generation. For MFA: acknowledged factor-set writes
 *   are not rolled back (no async-replica failover without `WAIT`, or the
 *   operator accepts that a failover may restore removed factors).
 *
 * The redis README, "MFA stores", states each for an operator.
 */
import { type MfaFactorStore } from "@o3co/auth-provider-core";
import type { MfaFactorStoreClient } from "./clients.mjs";
/** The key namespace `redisMfaFactorStore.keyPrefix` defaults to. */
export declare const DEFAULT_REDIS_MFA_FACTOR_STORE_KEY_PREFIX = "mfaf:";
export interface RedisMfaFactorStoreOptions {
    readonly client: MfaFactorStoreClient;
    /** Outer namespace; the subject's hash tag follows it. Without a brace. Default `mfaf:`. */
    readonly keyPrefix?: string;
}
/**
 * The adapter's write lifetime W (docs/adapter-surface.md, "Conditional
 * writes", rule 6): a membership write commits or fails within
 * {@link WRITE_TIMEOUT_MS} + {@link CLOCK_SKEW_MS} of its issue, while the
 * two clocks agree within the skew.
 */
export declare const REDIS_MFA_FACTOR_STORE_WRITE_LIFETIME_MS: number;
/**
 * The Redis {@link MfaFactorStore}. It resolves once the server's eviction
 * policy passes the gate (`internal/eviction-policy.mts`); an option it
 * cannot use rejects before the server is asked.
 */
export declare function createRedisMfaFactorStore(options: RedisMfaFactorStoreOptions): Promise<MfaFactorStore>;
/**
 * `defineModule` manifest for the Redis {@link MfaFactorStore}:
 * `mfaFactorStore` off the `mfaFactorStoreClient` slot (the shared socket
 * `makeIoredisClients` wraps or, preferably, a dedicated database or
 * instance), with its keys under `redis-mfa-factor-store.keyPrefix` (`mfaf:`),
 * its own section (strict).
 *
 * Declares no `replicaSafety`: every replica reads the one store, so a
 * composition with it may declare `core.deployment.mode = "multi"`. The store
 * is built by {@link createRedisMfaFactorStore}, so a server that fails the
 * eviction gate refuses the boot (`mfa-factor-store-evictable`); the
 * persistence notices (`internal/mfa-durability.mts`) then go to the `logger`
 * slot, or to `consoleLogger`.
 */
export declare const redisMfaFactorStoreModule: import("@o3co/auth-provider-core").Module;
//# sourceMappingURL=mfa-factor-store.d.mts.map