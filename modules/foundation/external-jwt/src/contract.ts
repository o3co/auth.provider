import { contract } from "@mod/kernel";
import { type VerifyAlgorithm, verifyAlgorithms } from "@mod/keys";
import type { Narrower } from "@mod/outbound";
import { z } from "zod";

export type Jwk = Readonly<Record<string, unknown>>;

/** An asymmetric JWS algorithm, one of those `keys` verifies under and `algorithms` lists. */
export type Algorithm = VerifyAlgorithm;

/** A key set at a URL, fetched only from the hosts named. */
export interface JwksSource {
	readonly url: string;
	readonly hosts: readonly string[];
	/** The operator's configured URL it is fetched for, so outbound may reach it as theirs. */
	readonly internal?: Narrower["internal"];
}

/** A public key written as PEM, taken only for the algorithm it is given for. */
export interface PemKey {
	readonly alg: Algorithm;
	readonly kid?: string;
	readonly pem: string;
}

/** Where the keys come from: written in, as PEM, or a key set at a URL. */
export type KeySource =
	| { readonly inline: readonly Jwk[] }
	| { readonly pem: readonly PemKey[] }
	| { readonly jwks: JwksSource };

/** What the caller decides: each value is the caller's own, given from its section. */
export interface Policy {
	readonly algorithms: readonly Algorithm[];
	/** How far the issuer's clock may be from `kernel`'s. */
	readonly skewMs: number;
	/** The longest a token may live: `exp` ahead of now, with the skew, and `exp` − `iat`, without it. */
	readonly maxLifetimeMs?: number;
	/** The header's `typ`, compared as RFC 7515 says. */
	readonly typ?: string;
	readonly expect?: {
		readonly iss?: string;
		/** Any one of these among the token's audiences. */
		readonly aud?: readonly string[];
		readonly sub?: string;
	};
}

export type Reason =
	| "malformed"
	| "algorithm"
	| "no-key"
	| "ambiguous-key"
	| "signature"
	| "expired"
	| "not-yet"
	| "future-iat"
	| "too-long"
	| "issuer"
	| "audience"
	| "subject";

/**
 * What a verifier answers: valid, invalid with its reason, or unavailable. An invalid answer found
 * once the signature held, a claim refused after it, carries `signed: true`; one before carries none.
 */
export type Verified =
	| {
			readonly kind: "valid";
			readonly header: Readonly<Record<string, unknown>>;
			readonly claims: Readonly<Record<string, unknown>>;
	  }
	| {
			readonly kind: "invalid";
			readonly reason: Reason;
			readonly signed?: true;
	  }
	| { readonly kind: "unavailable" };

export interface Verifier {
	verify(jwt: string): Promise<Verified>;
}

/** Makes verifiers; one per process, keeping each key set once, by its URL and hosts. */
export interface ExternalJwt {
	verifierOf(keys: KeySource, policy: Policy): Verifier;
	/** The asymmetric algorithms it knows; a policy may name any of them. */
	readonly algorithms: readonly Algorithm[];
}

export const externalJwt = contract<ExternalJwt>("external-jwt");

/** The asymmetric algorithms a verifier knows, as `algorithms` answers them, for a section declared before any verifier is had. */
export const knownAlgorithms: readonly Algorithm[] = verifyAlgorithms;

/**
 * The setting a caller's section names the algorithms it takes by: a list, not empty, of the
 * asymmetric ones given (never none nor a shared secret), `byDefault` where unwritten. A default
 * outside them is refused as one the operator wrote is. The caller describes it in its own words.
 */
export const algorithmsSetting = (
	asymmetric: readonly Algorithm[],
	byDefault: readonly Algorithm[],
) =>
	z
		.array(z.enum(asymmetric as [Algorithm, ...Algorithm[]]))
		.min(1)
		.prefault([...byDefault]);

/**
 * A header's `typ` as RFC 7515 compares it, as a media type: its type alone, its parameters and the
 * space around it dropped, without case and without `application/`; the one reading a policy's `typ`
 * is compared by, for a caller to sort tokens by. None where it is no string. Whether the header is
 * verified is the caller's to know.
 */
export const typOf = (header: Readonly<Record<string, unknown>>): string | undefined => {
	const typ = Object.hasOwn(header, "typ") ? header.typ : undefined;
	return typeof typ === "string"
		? (typ.split(";", 1)[0] ?? "")
				.trim()
				.toLowerCase()
				.replace(/^application\//, "")
		: undefined;
};
