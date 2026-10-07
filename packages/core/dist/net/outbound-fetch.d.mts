import { type OutboundPolicy, type OutboundUrlSource } from "./outbound-policy.mjs";
import { type OutboundTransport } from "./outbound-transport.mjs";
export type { OutboundUrlSource } from "./outbound-policy.mjs";
/** What a fetch is built for, beside the policy it follows. */
interface OutboundFetchUse {
    /**
     * Where the URLs this fetch is handed come from: `"registration"` (a
     * client registration) may use `core.outbound.internalHosts`;
     * `"request"` (a URL a request names) never does.
     */
    readonly source: OutboundUrlSource;
    /** This use's deadline in milliseconds, at most `core.outbound.timeoutMs` (the smaller applies). */
    readonly timeoutMs?: number;
    /** This use's cap on a 2xx body in bytes, at most `core.outbound.maxResponseBytes` (the smaller applies). */
    readonly maxResponseBytes?: number;
}
/**
 * The policy a fetch follows, given exactly one way: `config`, the
 * composition's configuration, whose `core.outbound` is read (an absent
 * section reads as the defaults), or `policy`, the policy core read from it
 * (the `outboundPolicy` slot).
 */
export type OutboundFetchOptions = OutboundFetchUse & ({
    readonly config: unknown;
    readonly policy?: undefined;
} | {
    readonly policy: OutboundPolicy;
    readonly config?: undefined;
});
/**
 * The seams below the policy: name resolution, the places it is run under
 * (`lookups`, the process-wide pool for the public factory), and the exchange.
 */
export interface OutboundFetchSeams {
    readonly lookup: (hostname: string) => Promise<readonly string[]>;
    readonly lookups: LookupPermits;
    readonly transport: OutboundTransport;
}
/** Every address the system resolver answers for `hostname`, both families, in its order. */
export declare const systemLookup: (hostname: string) => Promise<readonly string[]>;
/**
 * How many host-name resolutions the process may have outstanding, for
 * `UV_THREADPOOL_SIZE` as the process started with it (see
 * `threadpoolSizeOf`): two fewer than the threadpool, and at least one. The
 * system resolver runs on that threadpool, which bcrypt and the file system
 * share, and it cannot be cancelled: a lookup the deadline gave up on keeps
 * its thread until it settles. libuv runs host-name resolution on at most
 * `(n + 1) / 2` of its `n` threads; this bound keeps the outbound fetch's
 * own lookups finite, those nobody waits for any more included, and with the
 * request share ({@link REQUEST_LOOKUP_SHARE}) keeps a URL a client supplies
 * from holding more than one. With a pool of 1 or 2 threads, hung lookups can
 * still occupy the threads libuv gives such work, which is why the README
 * asks a deployment with Client ID Metadata Documents for the default size or
 * more.
 */
export declare function lookupCeilingOf(threadpoolSize: string | undefined): number;
/**
 * How many lookups for URLs a request names (`source: "request"`) may be
 * outstanding at once, within the process's bound, each counted until it
 * really settles; the rest of the bound is left to URLs from client
 * registrations. A request's URL comes from the request, a registration's
 * from the operator: request URLs whose resolver never answers hold this one
 * place and no other. When the bound is a single place, the
 * share is none, and a request's lookup fails with `timeout` at once.
 */
export declare const REQUEST_LOOKUP_SHARE = 1;
/**
 * How many calls may wait for a place among the outstanding lookups, across
 * the process. A call that finds this many already waiting fails with
 * `timeout` at once, without waiting and without starting a lookup: each
 * waiter holds a listener and its call's deadline, so the queue is bounded as
 * the lookups are. Fixed, not configured.
 */
export declare const MAX_WAITING_LOOKUPS = 64;
/**
 * How many of the {@link MAX_WAITING_LOOKUPS} may be calls for URLs a
 * request names; the rest stay free for registrations to wait in.
 */
export declare const MAX_REQUEST_WAITING_LOOKUPS = 48;
/**
 * The policy `config` states in `core.outbound`: an absent section (or no
 * configuration) reads as the defaults; a present one is validated and
 * refused, naming the key, when it does not parse. Frozen all the way down.
 */
export declare function outboundPolicyOf(config: unknown): OutboundPolicy;
/** The deadline and the body cap `core.outbound` sets: the ceilings over every use's own. */
export interface OutboundLimits {
    readonly timeoutMs: number;
    readonly maxResponseBytes: number;
}
/**
 * The limits `config` states in `core.outbound`, as the outbound fetch
 * applies them (the defaults for an absent section). Refuses a malformed
 * section, naming the key, as building the fetch does.
 */
export declare function outboundLimitsOf(config: unknown): OutboundLimits;
/** Lookups run under a bounded number of places; see {@link createLookupPermits}. */
export type LookupPermits = (lookup: OutboundFetchSeams["lookup"], hostname: string, source: OutboundUrlSource, signal: AbortSignal) => Promise<readonly string[]>;
/**
 * A pool of `max` places for outstanding lookups, of which a request's URL
 * may hold {@link REQUEST_LOOKUP_SHARE} (none when `max` is 1), with at most
 * `maxWaiting` calls waiting, `maxRequestWaiting` of them for a request's
 * URL. A place is taken before a lookup starts and given back only when the
 * lookup settles. A freed place goes to the longest-waiting call that may
 * take it: a request's call waits on while the request share is full, and a
 * registration's call behind it goes first. Each source's waiters are a
 * `Set`, which keeps arrival order and drops a cancelled one in constant time.
 */
export declare function createLookupPermits(max: number, maxWaiting?: number, maxRequestWaiting?: number): LookupPermits;
/**
 * The outbound fetch over `seams`. The public factory passes the system
 * resolver and Node's transport; the testing entry passes its own.
 */
export declare function buildOutboundFetch(options: OutboundFetchOptions, seams: OutboundFetchSeams): typeof fetch;
/**
 * A `fetch` that only reaches destinations `core.outbound` admits, for URLs
 * from `options.source`, read from `options.config` or given as
 * `options.policy`. Throws a `TypeError` unless exactly one of the two is
 * given, an `Error` when `core.outbound` is malformed, and when
 * `HTTPS_PROXY` or `HTTP_PROXY` is set without `core.outbound.egress = "direct"`.
 *
 * It takes a string or `URL` (a `Request` is a `TypeError`), `GET` or
 * `POST`, a string, `URLSearchParams` or `Uint8Array` body, any headers, and
 * a `signal`; redirects are never followed. A caller's abort rejects with its
 * own reason; the deadline is the shorter of the caller's and this one's.
 */
export declare function createOutboundFetch(options: OutboundFetchOptions): typeof fetch;
/** Whether `err` is the outbound fetch refusing a destination or an answer, as against the exchange failing. */
export declare function isOutboundRefusal(err: unknown): boolean;
//# sourceMappingURL=outbound-fetch.d.mts.map