/**
 * Reading the peer's certificate **chain** from the TLS session (#341, the
 * "Related: TLS-layer chains" section).
 *
 * Before this, `mode = "pki"` with `source = "tls-layer"` was refused at boot:
 * the narrow walk needed intermediates, and the only place it knew to find
 * them was the Envoy XFCC `Chain=` parameter. That left the RFC 8705 §3 shape
 * — terminate TLS here, take the certificate from the handshake — unable to
 * use PKI validation at all, even though #280 had just made `tls-layer` the
 * default source.
 *
 * `getPeerCertificate(true)` returns the chain as a linked list through
 * `issuerCertificate`. Two things about that list need care:
 *
 *  - **It is circular at the root.** A self-signed anchor's
 *    `issuerCertificate` points at itself, so a walk that only tests for
 *    `undefined` never terminates.
 *  - **It is peer-supplied.** The client chooses what to send, so the walk is
 *    bounded by depth rather than trusted to be short.
 *
 * The anchor the client sent is deliberately kept in the returned chain and
 * *not* treated as trusted. Trust comes from `oauth.mtls.trusted-cas` alone;
 * a chain that terminates in an anchor the operator did not configure fails
 * path validation, which is the whole point of configuring them.
 */
/** The shape of `getPeerCertificate(true)` that this module reads. */
export interface DetailedPeerCertificateLike {
    readonly raw?: Buffer;
    readonly issuerCertificate?: DetailedPeerCertificateLike;
}
export interface PeerChain {
    readonly leafDer: Uint8Array;
    /** Intermediates and any anchor the peer sent, nearest-issuer first. */
    readonly chainDer: readonly Uint8Array[];
}
/**
 * @param maxDepth total certificates to read, leaf included. A peer that
 * sends more has the remainder ignored rather than the request refused: path
 * validation bounds the chain it will accept anyway, and refusing here would
 * turn a verbose-but-valid client into an error at a layer that cannot
 * explain itself.
 */
export declare const peerChainFrom: (peer: DetailedPeerCertificateLike | undefined, maxDepth: number) => PeerChain | null;
//# sourceMappingURL=tlsChain.d.mts.map