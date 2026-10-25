import { contract } from "@mod/kernel";
import type { VerifyAlgorithm } from "@mod/keys";
import type { Narrower } from "@mod/outbound";

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

export type Verified =
	| {
			readonly kind: "valid";
			readonly header: Readonly<Record<string, unknown>>;
			readonly claims: Readonly<Record<string, unknown>>;
	  }
	| {
			readonly kind: "invalid";
			readonly reason: Reason;
			/** Present where the signature held and a claim was refused after; absent for a refusal before. */
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
