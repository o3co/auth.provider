import { contract, extensionPoint } from "@mod/kernel";
import { type VerifyAlgorithm, verifyAlgorithms } from "@mod/keys";

/** A signing algorithm: an asymmetric one `keys` verifies. */
export type SignerAlgorithm = VerifyAlgorithm;

/** The signing algorithms the grant takes by default, one for each kind of key. */
export const algorithms = ["EdDSA", "ES256", "RS256"] as const satisfies readonly SignerAlgorithm[];

/** Every signing algorithm there is to take: the asymmetric ones `keys` verifies. */
export const takenAlgorithms: readonly SignerAlgorithm[] = verifyAlgorithms;

/** A public key as a JWK. */
export type SignerKey = Readonly<Record<string, unknown>>;

/**
 * The keys of the signers of one issuer, asked for each assertion it names. A signer is asked by
 * its `subject` (the assertion's `sub`; its key's thumbprint where the issuer's subject is one) and
 * the assertion's `kid`.
 */
export interface SignerKeys {
	/** The `iss` it answers for. */
	readonly issuer: string;
	/**
	 * Declared where it answers each signer's own keys alone: a key it answers for one subject is
	 * never answered for another. A promise of what it reads the keys from.
	 */
	readonly perSigner?: true;
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

/** An assertion as its issuer's ledger is asked to use it up: its jti as sent, and how long it stays used. */
export interface SpendingAssertion {
	/** The `iss` as the assertion sent it. */
	readonly sentIssuer: string;
	/** As sent: 1 to 256 well-formed characters. */
	readonly jti: string;
	/** The assertion's `exp`, in ms. */
	readonly expiresAt: number;
	/** Until when it must stay used, in ms: its `exp`, the clock skew allowed, and a margin. */
	readonly keepUntil: number;
}

/**
 * One issuer's ledger of the assertions used up, shared with whatever else accepts them: in place of
 * the store, for that issuer's assertions alone.
 */
export interface JtiLedger {
	/** The `iss` it answers for: one of the section's `issuers`. */
	readonly issuer: string;
	/**
	 * Uses the assertion up: `first` where it was not used before, `replayed` where it was. Throws
	 * Unavailable when it cannot tell; one whose answer is lost may stay used. Asked once the
	 * assertion is verified and every check before issuing has passed.
	 */
	spend(assertion: SpendingAssertion): Promise<"first" | "replayed">;
}

export const jtiLedgers = extensionPoint<JtiLedger>("jwt-bearer.jti-ledgers", {
	multiplicity: "keyed",
	keyOf: (ledger) => ledger.issuer,
});

/**
 * What a delegate makes of an assertion it checked by its own rules: the account it is for, when it
 * was made and ends (ms), the clients of this provider it is for, and the digest of a key its holder
 * must prove (`BASE64URL(SHA-256(jkt))`).
 */
export type DelegatedCheck =
	| {
			readonly kind: "valid";
			readonly subject: string;
			readonly issuedAt: number;
			readonly expiresAt: number;
			readonly clients: readonly [string, ...string[]];
			readonly holderDigest?: string;
	  }
	| { readonly kind: "invalid" };

/**
 * Assertions another module checks by its own rules, for issuers the section's `delegated-issuers`
 * names. Their audience is an app, never this server, so RFC 7523 §3 does not hold: jwt-bearer reads
 * neither their audience nor their `jti`, and leaves their single use to the delegate.
 */
export interface DelegatedAssertions {
	/** The contributing module's name, told where boot is refused. */
	readonly declaredBy: string;
	/** The `iss` values it checks, each as sent. */
	readonly issuers: readonly string[];
	/** Checks signature, audience, times and subject; throws Unavailable when it cannot tell. */
	check(assertion: string): Promise<DelegatedCheck>;
	/**
	 * Uses the assertion up: `spent` the first time, `replayed` after. Throws Unavailable when it cannot
	 * tell; one whose answer is lost may stay used. Asked once every check before issuing has passed.
	 */
	spend(assertion: string): Promise<"spent" | "replayed">;
}

/** Counted by jwt-bearer: exactly one for each delegated issuer. */
export const delegatedAssertions = extensionPoint<DelegatedAssertions>(
	"jwt-bearer.delegated-assertions",
	{ multiplicity: "many" },
);

export * from "./store.ts";
