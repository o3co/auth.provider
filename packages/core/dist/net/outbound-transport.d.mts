/** One exchange, as the policy admitted it. */
export interface OutboundExchange {
    readonly url: URL;
    /** The TLS server name: the host for a name, `undefined` for an IP literal. */
    readonly servername: string | undefined;
    /** The addresses the policy checked; the connection goes to one of these and nowhere else. */
    readonly addresses: readonly string[];
    readonly method: "GET" | "POST";
    readonly headers: Readonly<Record<string, string>>;
    readonly body: Uint8Array | undefined;
    /** Ends the exchange at any point: before the answer, or while its body is read. */
    readonly signal: AbortSignal;
}
/** The peer's answer, its body not yet read. */
export interface OutboundAnswer {
    readonly status: number;
    readonly statusText: string;
    readonly headers: readonly (readonly [string, string])[];
    /** The body as it arrives; read at most once. */
    readonly body: AsyncIterable<Uint8Array>;
    /** Releases the connection whether or not the body was read. Idempotent. */
    close(): void;
}
export type OutboundTransport = (exchange: OutboundExchange) => Promise<OutboundAnswer>;
/**
 * The transport over Node's own HTTP stack. `tls.ca` replaces the trust
 * store, for tests that run a TLS peer with a certificate of their own.
 */
export declare function createNodeTransport(tls?: {
    readonly ca?: string;
}): OutboundTransport;
/** The transport the public factory uses. */
export declare const nodeTransport: OutboundTransport;
//# sourceMappingURL=outbound-transport.d.mts.map