import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Server-provided nonces (RFC 9449 §8): `<bucket>.<mac>`, the time bucket and an HMAC over it under
 * a secret every instance shares, so nothing is kept and any instance verifies another's. A nonce
 * of the current bucket or the one before is taken; replay is the jti's to refuse.
 */
/** Makes the current nonce, and tells whether one was made here within its bucket or the one before. */
export interface Nonces {
	issue(): string;
	verify(nonce: string): boolean;
}

export function nonces(secret: Uint8Array, bucketMs: number, now: () => number): Nonces {
	const bucketNow = () => Math.floor(now() / bucketMs);
	const macOf = (bucket: number) =>
		createHmac("sha256", secret).update(`dpop-nonce:${bucket}`).digest();
	const nonceOf = (bucket: number) => `${bucket}.${macOf(bucket).toString("base64url")}`;
	return {
		// The clock is read once, so the bucket named and the one signed are the same.
		issue: () => nonceOf(bucketNow()),
		verify: (nonce: string) => {
			const [head, mac, ...rest] = nonce.split(".");
			if (rest.length > 0 || mac === undefined || head === undefined || !/^\d+$/.test(head)) {
				return false;
			}
			const bucket = Number(head);
			const current = bucketNow();
			if (bucket !== current && bucket !== current - 1) return false;
			const presented = Buffer.from(mac, "base64url");
			const expected = macOf(bucket);
			return presented.length === expected.length && timingSafeEqual(presented, expected);
		},
	};
}
