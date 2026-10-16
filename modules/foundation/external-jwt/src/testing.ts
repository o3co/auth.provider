import { generateKeyPairSync, type KeyObject, sign } from "node:crypto";

/** What differs by algorithm: the key pair, the digest, and how an EC signature is written (RFC 7518 §3.4). */
const byAlg = {
	ES256: {
		pair: () => generateKeyPairSync("ec", { namedCurve: "P-256" }),
		digest: "sha256",
		encoding: { dsaEncoding: "ieee-p1363" as const },
	},
	RS256: {
		pair: () => generateKeyPairSync("rsa", { modulusLength: 2048 }),
		digest: "sha256",
		encoding: {},
	},
	EdDSA: { pair: () => generateKeyPairSync("ed25519"), digest: null, encoding: {} },
};
type TestAlgorithm = keyof typeof byAlg;

const encoded = (text: string) => Buffer.from(text).toString("base64url");

/**
 * A key pair for a test: its public key as a JWK (with `kid` where given) and as PEM, and signers
 * that write any header as a sender might, unencoded payloads and critical extensions included.
 */
export async function testSigner(alg: TestAlgorithm, kid?: string) {
	const { publicKey, privateKey }: { publicKey: KeyObject; privateKey: KeyObject } =
		byAlg[alg].pair();
	const jwk: Record<string, unknown> = {
		...publicKey.export({ format: "jwk" }),
		...(kid ? { kid } : {}),
	};
	return {
		jwk,
		pem: publicKey.export({ format: "pem", type: "spki" }).toString(),
		/** Signs the claims; `header` adds to or, with undefined, removes from `{ alg, kid }`. */
		sign: async (claims: unknown, header: Record<string, unknown> = {}) =>
			signed(Buffer.from(JSON.stringify(claims)), header),
		/** Signs a payload's exact bytes, which no JSON value can carry; `header` is as for `sign`. */
		signBytes: async (payload: Uint8Array, header: Record<string, unknown> = {}) =>
			signed(payload, header),
	};

	function signed(payload: Uint8Array, header: Record<string, unknown>) {
		const written: Record<string, unknown> = Object.fromEntries(
			Object.entries({ alg, ...(kid ? { kid } : {}), ...header }).filter(
				([, value]) => value !== undefined,
			),
		);
		const body = Buffer.from(payload);
		const input = `${encoded(JSON.stringify(written))}.${written.b64 === false ? body.toString() : body.toString("base64url")}`;
		const { digest, encoding } = byAlg[alg];
		const signature = sign(digest, Buffer.from(input), { key: privateKey, ...encoding });
		return `${input}.${signature.toString("base64url")}`;
	}
}
