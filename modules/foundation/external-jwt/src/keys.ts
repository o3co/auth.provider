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

/**
 * The one algorithm a key is read under (RFC 8725 §3.1): its own `alg` where allowed, else the one
 * allowed algorithm its kind and curve fit; none where it names none and two or more fit.
 */
function boundTo(jwk: Jwk, allowed: readonly Algorithm[]): Algorithm | undefined {
	if (jwk.alg !== undefined) return allowed.find((a) => a === jwk.alg && verifiesUnder(jwk, a));
	const fitting = [...new Set(allowed)].filter((a) => verifiesUnder(jwk, a));
	return fitting.length === 1 ? fitting[0] : undefined;
}

/**
 * The one key that may verify under the header's algorithm and id, each fitting by its kind, curve,
 * use and id, and read under its one algorithm among those allowed. `unbound`: the key the `kid`
 * names is read under another algorithm, or none, which a fresh set would not change.
 */
export function picked(
	candidates: readonly Candidate[],
	alg: Algorithm,
	kid: string | undefined,
	allowed: readonly Algorithm[],
): Candidate | "no-key" | "ambiguous-key" | "unbound" {
	const fit = candidates.filter(({ jwk }) => {
		const { alg: _named, ...unnamed } = jwk;
		return verifiesUnder(unnamed, alg) && (kid === undefined || jwk.kid === kid);
	});
	const [only, ...more] = fit.filter(({ jwk }) => boundTo(jwk, allowed) === alg);
	if (!only) return fit.length > 0 && kid !== undefined ? "unbound" : "no-key";
	return more.length > 0 ? "ambiguous-key" : only;
}
