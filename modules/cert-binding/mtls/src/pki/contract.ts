/** What a client certificate is held to. */
export interface PathPolicy {
	/** Trust anchors (DER); a peer never sends one that counts. */
	readonly anchors: readonly Uint8Array[];
	/** At most this many certificates between the leaf and an anchor. */
	readonly maxIntermediates: number;
	readonly minRsaBits: number;
}

export interface RevocationPolicy {
	readonly mode: "crl" | "ocsp" | "both";
	readonly nonce: boolean;
	readonly skewMs: number;
	/** How long an OCSP answer without a next update is taken. */
	readonly ocspFreshMs: number;
	/** How long a CRL is kept at most, its next update aside. */
	readonly crlTtlMs: number;
	/** How long a source that failed is not asked again. */
	readonly failureMs: number;
	readonly crlEntries: number;
	readonly ocspEntries: number;
	/** How many sources one check may fetch from; past them, what is left is unconfirmed. */
	readonly maxFetches: number;
}

/** What a source gave: its material, an outage, or a refusal (a destination not allowed and the like). */
export type Fetched =
	| { readonly kind: "material"; readonly body: Uint8Array }
	| { readonly kind: "outage" | "refused" };

/** Where revocation material comes from: a GET, or a POST of `body`. */
export interface Sources {
	fetch(url: string, body?: Uint8Array): Promise<Fetched>;
	now(): number;
	random(n: number): Uint8Array;
}

/** A certificate's path and revocation: valid, refused for a reason, revoked, or an outage of its sources. */
export type Checked =
	| { readonly kind: "valid" }
	| { readonly kind: "revoked" }
	| { readonly kind: "invalid" | "outage"; readonly reason: string };

export interface Pki {
	/** Checks the leaf through the chain sent to an anchor, and its revocation, as of `now`. */
	check(leaf: Uint8Array, chain: readonly Uint8Array[], now: number): Promise<Checked>;
}
