import type { ExternalJwt, JwksSource, PemKey, Policy, Verifier } from "@mod/external-jwt";
import { isUnavailable, Unavailable } from "@mod/kernel";
import { thumbprint as keyThumbprint, publicPem } from "@mod/keys";
import {
	type SignerAlgorithm,
	type SignerKey,
	type SignerKeys,
	takenAlgorithms,
} from "./contract.ts";

/** A JWK thumbprint's shape (RFC 7638, SHA-256): 43 characters of base64url. */
export const isThumbprint = (value: string) => /^[A-Za-z0-9_-]{43}$/.test(value);

/**
 * An assertion's signer, read unverified: `lookup`, the subject its keys are asked by (its key's
 * thumbprint where its issuer says so); `expectedSub`, the `sub` its signature must hold; `kid`.
 */
export interface Signer {
	readonly lookup: string;
	readonly expectedSub: string;
	readonly kid: string | undefined;
}

/** One issuer's signers: the verifier for an assertion's signer, picked before anything is verified. */
export interface Signers {
	/** Whether a signer's subject is its signing key's JWK thumbprint. */
	readonly thumbprint: boolean;
	/** None where no key is known for the signer; throws Unavailable where that cannot be told. */
	verifierFor(signer: Signer): Promise<Verifier | undefined>;
}

const thumbprintOf = (jwk: SignerKey) => keyThumbprint(jwk).catch(() => undefined);

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
		const read = publicPem(key.pem);
		const own = read && (await keyThumbprint(read).catch(() => undefined));
		if (own) byThumbprint.set(own, jwt.verifierOf({ pem: [key] }, policy));
	}
	return { thumbprint, verifierFor: async (signer) => byThumbprint.get(signer.lookup) };
}

/** A key set fetched from its URL. */
export function fetchedSigners(jwt: ExternalJwt, jwks: JwksSource, policy: Policy): Signers {
	const verifier = jwt.verifierOf({ jwks }, policy);
	return { thumbprint: false, verifierFor: async () => verifier };
}

const taken = (given: unknown): given is readonly SignerAlgorithm[] =>
	Array.isArray(given) && given.every((a) => (takenAlgorithms as readonly unknown[]).includes(a));

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
		verifierFor: async ({ lookup, expectedSub, kid }) => {
			const answer = await asked(lookup, kid);
			if (answer?.kind === "none") return undefined;
			if (answer?.kind !== "keys" || !Array.isArray(answer.keys) || !taken(answer.algorithms)) {
				throw new Unavailable("jwt-bearer");
			}
			const chosen: SignerKey[] = [];
			for (const key of answer.keys) {
				if (!thumbprint || (await thumbprintOf(key)) === lookup) chosen.push(key);
			}
			// Taken under what both the answer and the issuer's policy take; none, and the keys are no keys.
			const both = answer.algorithms.filter((a) => policy.algorithms.includes(a));
			if (chosen.length === 0 || both.length === 0) return undefined;
			return jwt.verifierOf(
				{ inline: chosen },
				{
					...policy,
					algorithms: both,
					expect: { ...policy.expect, sub: expectedSub },
				},
			);
		},
	};
}
