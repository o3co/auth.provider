import { contract, extensionPoint } from "@mod/kernel";

/** The signing algorithms the grant takes. */
export const algorithms = ["EdDSA", "ES256", "RS256"] as const;
export type SignerAlgorithm = (typeof algorithms)[number];

/** A public key as a JWK. */
export type SignerKey = Readonly<Record<string, unknown>>;

/** The keys of the signers of one issuer, asked for each assertion it names; a signer is the assertion's `sub` and `kid`. */
export interface SignerKeys {
	/** The `iss` it answers for. */
	readonly issuer: string;
	/**
	 * The signer's keys and the algorithms they take; none for a signer with no keys, unknown or
	 * revoked. Throws Unavailable when it cannot tell. Asked with a subject already well formed, and
	 * never kept between assertions.
	 */
	keysOf(signer: { readonly subject: string; readonly kid?: string }): Promise<
		| {
				readonly kind: "keys";
				readonly keys: readonly SignerKey[];
				readonly algorithms: readonly SignerAlgorithm[];
		  }
		| { readonly kind: "none" }
	>;
}

export const signerKeys = extensionPoint<SignerKeys>("jwt-bearer.signer-keys", {
	multiplicity: "keyed",
	keyOf: (keys) => keys.issuer,
});

/** The subject a linked issuer's verified signer stands for, by the IdP name its signers are known by. */
export interface LinkedSubjects {
	/** The contributing module's name, told where boot is refused. */
	readonly declaredBy: string;
	/** None where no subject is linked to the signer; throws Unavailable when it cannot tell. */
	subjectOf(
		upstream: string,
		sub: string,
	): Promise<{ readonly kind: "subject"; readonly subject: string } | { readonly kind: "none" }>;
}

/** Counted by jwt-bearer: one where an issuer is linked, any where none is. */
export const linkedSubjects = extensionPoint<LinkedSubjects>("jwt-bearer.subjects", {
	multiplicity: "many",
});

/** The linked issuers of the section, each with the IdP name (`upstream`) its signers are known by. */
export type LinkedIssuers = readonly { readonly upstream: string; readonly issuer: string }[];

export const linkedIssuers = contract<LinkedIssuers>("jwt-bearer.linked-issuers");

export * from "./store.ts";
