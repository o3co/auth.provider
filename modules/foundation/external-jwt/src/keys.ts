import type { KeyObject } from "node:crypto";
import {
	isVerifyAlgorithm,
	publicJwk,
	publicPem,
	verifiesUnder,
	verifyAlgorithms,
} from "@mod/keys";
import type { Algorithm, Jwk, PemKey } from "./contract.ts";

/** A key that may verify: as a JWK, for choosing it, and as the platform reads it. */
export interface Candidate {
	readonly jwk: Jwk;
	readonly key: KeyObject;
}

/** The asymmetric algorithms `keys` knows. */
export const algorithms: readonly Algorithm[] = verifyAlgorithms;

export const isAlgorithm = (alg: unknown): alg is Algorithm => isVerifyAlgorithm(alg);

/** A public key `keys` reads from a JWK; none for anything else. */
export const fromJwk = (jwk: Jwk): Candidate | undefined => publicJwk(jwk);

/** A PEM public key, taken only for the algorithm it is given for; a private one never is. */
export function fromPem(given: PemKey): Candidate | undefined {
	const key = publicPem(given.pem);
	if (!key) return undefined;
	const jwk = {
		...key.export({ format: "jwk" }),
		alg: given.alg,
		...(given.kid ? { kid: given.kid } : {}),
	};
	return { jwk, key };
}

/** The one key that may verify under the header's algorithm and id. */
export function picked(
	candidates: readonly Candidate[],
	alg: Algorithm,
	kid: string | undefined,
): Candidate | "no-key" | "ambiguous-key" {
	const matching = candidates.filter(
		({ jwk }) => verifiesUnder(jwk, alg) && (kid === undefined || jwk.kid === kid),
	);
	const [only, ...more] = matching;
	if (!only) return "no-key";
	return more.length > 0 ? "ambiguous-key" : only;
}
