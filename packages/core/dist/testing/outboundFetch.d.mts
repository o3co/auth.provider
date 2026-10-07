/**
 * The outbound fetch for tests: the same policy over a resolver and a
 * transport a test supplies (both below the policy, so every rule still
 * applies), the error class a test asserts on, and the builder a test writes
 * `core.outbound` with.
 */
import type { z } from "zod";
import { type OutboundFetchOptions } from "../net/outbound-fetch.mjs";
import type { OutboundSectionSchema } from "../net/outbound-policy.mjs";
import { type OutboundTransport } from "../net/outbound-transport.mjs";
export { OutboundFetchError } from "../net/outbound-policy.mjs";
export type { OutboundAnswer, OutboundExchange, OutboundTransport, } from "../net/outbound-transport.mjs";
export type OutboundFetchForTestingOptions = OutboundFetchOptions & {
    /** Answers a host name with its addresses; absent → the system resolver. */
    readonly lookup?: (hostname: string) => Promise<readonly string[]>;
    /** Performs the exchange with the checked addresses; absent → Node's own. */
    readonly transport?: OutboundTransport;
};
/**
 * `createOutboundFetch`, with the resolver and the transport replaced where
 * given. Its lookups run under a pool of its own, bounded as the process's
 * is, so a lookup one test leaves outstanding never holds a place another
 * test's fetch needs.
 */
export declare function createOutboundFetchForTesting(options: OutboundFetchForTestingOptions): typeof fetch;
/** `core.outbound` as a test writes it. */
export type OutboundSectionForTests = z.input<typeof OutboundSectionSchema>;
/**
 * A copy of `config` whose `core.outbound` is `outbound`, every other key of
 * `core` and of `config` kept; `config` itself is left as it was.
 */
export declare function withOutbound<C extends object>(config: C, outbound: OutboundSectionForTests): C & {
    readonly core: {
        readonly outbound: OutboundSectionForTests;
    };
};
//# sourceMappingURL=outboundFetch.d.mts.map