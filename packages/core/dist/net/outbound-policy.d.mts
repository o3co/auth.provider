import { z } from "zod";
/** Where a URL came from: decides whether `internalHosts` may apply. */
export type OutboundUrlSource = "registration" | "request";
/** The policy refusing a destination or an answer. */
type OutboundRefusalReason = "url_unparseable" | "scheme_not_allowed" | "userinfo_present" | "port_not_allowed" | "host_not_allowed" | "special_use_address" | "redirect_refused" | "response_too_large" | "unsupported_encoding";
/** The exchange failing for a reason that is not the policy's. */
type OutboundFailureReason = "resolution_failed" | "timeout" | "network_error";
export type OutboundFetchErrorReason = OutboundRefusalReason | OutboundFailureReason;
/**
 * A refusal or failure of the outbound fetch. `reason` is a code
 * (`loggableError` keeps it); the message is core's own words and the host,
 * never anything the peer sent.
 */
export declare class OutboundFetchError extends Error {
    readonly name = "OutboundFetchError";
    readonly reason: OutboundFetchErrorReason;
    constructor(reason: OutboundFetchErrorReason, host?: string, detail?: string);
    /** Whether this is the policy refusing, as against the exchange failing. */
    get refusal(): boolean;
}
/** One host-list entry: a canonical host, and whether it also covers every subdomain. */
export interface HostPattern {
    readonly host: string;
    readonly suffix: boolean;
}
/**
 * The canonical form of `url`'s host, as host lists are matched: the URL
 * parser's (lower case, punycode, canonical IPv4 and bracketed IPv6) with one
 * trailing dot removed. `undefined` when a label is empty.
 */
export declare function urlHost(url: URL): string | undefined;
/**
 * `entry` read as a host-list entry: a host name of letters, digits and
 * hyphens once IDNA has run, an IPv4 address or an IPv6 address (bracketed
 * or not), optionally after a `.` that also covers every subdomain of a
 * name. `undefined` for anything else (a wildcard, a scheme, a port, a path,
 * credentials, an empty label, a suffix on an address).
 */
export declare function readHostEntry(entry: string): HostPattern | undefined;
/**
 * Whether `patterns` cover `host`, read as an entry is read (any URL's
 * `hostname`; a trailing dot, case and IP spellings alike). A host it cannot
 * read (an empty label, a port, a path) is a `TypeError`, for an allow list
 * and a deny list alike: the caller refuses such a URL.
 */
export declare function matchesHostList(patterns: readonly HostPattern[], host: string): boolean;
/** The longest deadline a timer holds: Node runs a longer one at once. */
export declare const MAX_TIMEOUT_MS = 2147483647;
/**
 * `core.outbound`, this policy's section: core's schema declares it under
 * `core`, and `outboundPolicyOf` (`outbound-fetch.mts`) alone reads it.
 * Strict, and each key optional: an absent key takes its default there, and
 * a present section that does not parse refuses boot. Each leaf reads the
 * string an environment variable carries.
 */
export declare const OutboundSectionSchema: z.ZodObject<{
    allowedHosts: z.ZodOptional<z.ZodPipe<z.ZodPipe<z.ZodUnion<readonly [z.ZodArray<z.ZodString>, z.ZodString]>, z.ZodTransform<string[], string | string[]>>, z.ZodArray<z.ZodString>>>;
    deniedHosts: z.ZodOptional<z.ZodPipe<z.ZodPipe<z.ZodUnion<readonly [z.ZodArray<z.ZodString>, z.ZodString]>, z.ZodTransform<string[], string | string[]>>, z.ZodArray<z.ZodString>>>;
    internalHosts: z.ZodOptional<z.ZodPipe<z.ZodPipe<z.ZodUnion<readonly [z.ZodArray<z.ZodString>, z.ZodString]>, z.ZodTransform<string[], string | string[]>>, z.ZodArray<z.ZodString>>>;
    timeoutMs: z.ZodOptional<z.ZodPipe<z.ZodPipe<z.ZodPipe<z.ZodUnion<readonly [z.ZodNumber, z.ZodString]>, z.ZodTransform<number, string | number>>, z.ZodNumber>, z.ZodNumber>>;
    maxResponseBytes: z.ZodOptional<z.ZodPipe<z.ZodPipe<z.ZodUnion<readonly [z.ZodNumber, z.ZodString]>, z.ZodTransform<number, string | number>>, z.ZodNumber>>;
    egress: z.ZodOptional<z.ZodEnum<{
        direct: "direct";
    }>>;
}, z.core.$strict>;
/**
 * The policy `core.outbound` states, its lists read into patterns: what
 * `outboundPolicyOf` (`outbound-fetch.mts`) answers, frozen all the way
 * down, and what the `outboundPolicy` slot holds.
 */
export interface OutboundPolicy {
    readonly allowedHosts: readonly HostPattern[];
    readonly deniedHosts: readonly HostPattern[];
    readonly internalHosts: readonly HostPattern[];
    readonly timeoutMs: number;
    readonly maxResponseBytes: number;
    readonly egress: "direct" | undefined;
}
/** A URL the policy admits, ready to be resolved and connected to. */
export interface AdmittedDestination {
    readonly url: URL;
    /** The canonical host, for the lists and the log. */
    readonly host: string;
    /** The address itself, when the host is an IP literal: nothing is resolved. */
    readonly literal: string | undefined;
    /** Whether the host may be at a special-use address. */
    readonly internal: boolean;
    /** Plain http: admitted only toward the loopback interface. */
    readonly plaintext: boolean;
}
/**
 * The URL `input` names, if the policy admits it before any name is
 * resolved: https (or http to a loopback host `internalHosts` lists, for a
 * registration's URL), no credentials, no bad port, the host lists, and an
 * IP-literal host outside the special-use ranges unless it is internal.
 * Throws an {@link OutboundFetchError} refusal otherwise.
 */
export declare function admitUrl(input: string, policy: OutboundPolicy, source: OutboundUrlSource): AdmittedDestination;
/**
 * Whether `addresses`, every address the destination's host resolved to,
 * may be connected to: each an IP address; none special-use unless the host
 * is internal (a mixed answer is refused: no address is picked from it);
 * each loopback for plain http. Throws an {@link OutboundFetchError} otherwise.
 */
export declare function admitAddresses(destination: AdmittedDestination, addresses: readonly string[]): void;
declare module "@o3co/auth-provider-core" {
    interface ComponentMap {
        /**
         * The outbound destination policy: filled by boot with
         * `outboundPolicyOf` over the configuration's `core.outbound` for every
         * composition, before any provider runs. A synthetic key: no module
         * provides it and no host map sets it (`synthetic-key-collision`).
         */
        readonly outboundPolicy?: OutboundPolicy;
    }
}
export {};
//# sourceMappingURL=outbound-policy.d.mts.map