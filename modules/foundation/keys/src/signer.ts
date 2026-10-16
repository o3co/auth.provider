import {
	CompactSign,
	compactVerify,
	decodeProtectedHeader,
	type ProtectedHeaderParameters,
} from "jose";
import type { Keys, VerifyResult } from "./contract.ts";
import { isCanonicalJws } from "./jws.ts";
import { expired, type Ring, type RingKey } from "./ring.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function headerOf(token: string): ProtectedHeaderParameters | undefined {
	try {
		return decodeProtectedHeader(token);
	} catch {
		return undefined;
	}
}

async function verifiedPayload(token: string, key: RingKey): Promise<Uint8Array | undefined> {
	try {
		return (await compactVerify(token, key.key, { algorithms: [key.alg] })).payload;
	} catch {
		return undefined;
	}
}

function claimsOf(payload: Uint8Array): unknown {
	try {
		return JSON.parse(decoder.decode(payload));
	} catch {
		return undefined;
	}
}

export function signer(ring: Ring, now: () => number): Omit<Keys, "keySetPath"> {
	// An HS256 secret verifies its own tokens; an asymmetric signing key verifies through its public half.
	const verifiers =
		ring.signing.alg === "HS256" ? [ring.signing, ...ring.publicKeys] : ring.publicKeys;
	const byKid = new Map(verifiers.map((k) => [k.kid, k]));
	return {
		asymmetric: () => ring.signing.alg !== "HS256",
		algorithm: () => ring.signing.alg,
		sign: (claims, typ) =>
			new CompactSign(encoder.encode(JSON.stringify(claims)))
				.setProtectedHeader({ alg: ring.signing.alg, typ, kid: ring.signing.kid })
				.sign(ring.signing.key),
		verify: async (token, typ): Promise<VerifyResult> => {
			const header = isCanonicalJws(token) ? headerOf(token) : undefined;
			if (!header) return { kind: "invalid", reason: "malformed" };
			if (header.typ !== typ) return { kind: "invalid", reason: "typ" };
			const key = typeof header.kid === "string" ? byKid.get(header.kid) : undefined;
			if (!key) return { kind: "invalid", reason: "kid_unknown" };
			if (expired(key, now)) return { kind: "invalid", reason: "kid_expired" };
			const payload = await verifiedPayload(token, key);
			if (!payload) return { kind: "invalid", reason: "signature" };
			const claims = claimsOf(payload);
			// Only a key holder can sign a payload that is not JSON; it is answered as a bad signature.
			if (claims === undefined) return { kind: "invalid", reason: "signature" };
			return { kind: "valid", claims: Object.freeze(claims) as Readonly<Record<string, unknown>> };
		},
	};
}
