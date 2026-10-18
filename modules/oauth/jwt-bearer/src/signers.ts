import type { ExternalJwt, JwksSource, PemKey, Policy, Verifier } from "@mod/external-jwt";
import { isUnavailable, Unavailable } from "@mod/kernel";
import { calculateJwkThumbprint, exportJWK, importSPKI, type JWK } from "jose";
import { algorithms, type SignerAlgorithm, type SignerKey, type SignerKeys } from "./contract.ts";

/** A JWK thumbprint's shape (RFC 7638, SHA-256): 43 characters of base64url. */
export const isThumbprint = (value: string) => /^[A-Za-z0-9_-]{43}$/.test(value);

/** One issuer's signers: the verifier for an assertion's signer, picked before anything is verified. */
export interface Signers {
	/** Whether a signer's subject is its signing key's JWK thumbprint. */
	readonly thumbprint: boolean;
	/** None where no key is known for the signer; throws Unavailable where that cannot be told. */
	verifierFor(subject: string, kid: string | undefined): Promise<Verifier | undefined>;
}

const thumbprintOf = (jwk: SignerKey) =>
	calculateJwkThumbprint(jwk as JWK, "sha256").catch(() => undefined);

/** Keys written in the section; with thumbprints, each key verifies only the subject that is its own. */
export async function writtenSigners(
	jwt: ExternalJwt,
	keys: readonly PemKey[],
	policy: Policy,
	thumbprint: boolean,
): Promise<Signers> {
	if (!thumbprint) {
		const verifier = jwt.verifierOf({ pem: keys }, policy);
		return { thumbprint, verifierFor: async () => verifier };
	}
	const byThumbprint = new Map<string, Verifier>();
	for (const key of keys) {
		const jwk = await exportJWK(await importSPKI(key.pem, key.alg));
		const own = await thumbprintOf(jwk);
		if (own) byThumbprint.set(own, jwt.verifierOf({ pem: [key] }, policy));
	}
	return { thumbprint, verifierFor: async (subject) => byThumbprint.get(subject) };
}

/** A key set fetched from its URL. */
export function fetchedSigners(jwt: ExternalJwt, jwks: JwksSource, policy: Policy): Signers {
	const verifier = jwt.verifierOf({ jwks }, policy);
	return { thumbprint: false, verifierFor: async () => verifier };
}

const taken = (given: unknown): given is readonly SignerAlgorithm[] =>
	Array.isArray(given) && given.every((a) => (algorithms as readonly unknown[]).includes(a));

/** Keys a module contributes, asked for each assertion, the subject checked against the verified one. */
export function contributedSigners(
	jwt: ExternalJwt,
	keys: SignerKeys,
	policy: Policy,
	thumbprint: boolean,
): Signers {
	const asked = async (subject: string, kid: string | undefined) => {
		try {
			return await keys.keysOf({ subject, ...(kid === undefined ? {} : { kid }) });
		} catch (error) {
			throw isUnavailable(error) ? error : new Unavailable("jwt-bearer");
		}
	};
	return {
		thumbprint,
		verifierFor: async (subject, kid) => {
			const answer = await asked(subject, kid);
			if (answer?.kind === "none") return undefined;
			if (answer?.kind !== "keys" || !Array.isArray(answer.keys) || !taken(answer.algorithms)) {
				throw new Unavailable("jwt-bearer");
			}
			const chosen: SignerKey[] = [];
			for (const key of answer.keys) {
				if (!thumbprint || (await thumbprintOf(key)) === subject) chosen.push(key);
			}
			if (chosen.length === 0) return undefined;
			return jwt.verifierOf(
				{ inline: chosen },
				{ ...policy, algorithms: answer.algorithms, expect: { ...policy.expect, sub: subject } },
			);
		},
	};
}
