/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Server-provided DPoP nonces (RFC 9449 §8 / §9, #530).
 *
 * Without a nonce the only freshness control on a proof is `iat` skew, which
 * is weak for a token that lives longer than a few minutes: a proof minted
 * ahead of time stays usable for the whole window. A nonce the server hands
 * out and the client has to echo bounds pre-generation to the nonce's own
 * lifetime instead.
 *
 * ## Stateless by construction
 *
 * A nonce is `<bucket>.<mac>`: the current time bucket and an HMAC over it
 * under a secret every replica shares. Verifying one is recomputing the MAC,
 * so nothing is stored and nothing is looked up — a nonce minted by one
 * replica verifies on every other, and there is no store to be unavailable
 * on the proof path. The cost is that a nonce is not single-use; it is not
 * meant to be — replay of the *proof* is what `jti` and the replay store
 * refuse, and the nonce only says "this proof was made after this instant".
 *
 * ## Rotation
 *
 * The bucket advances every `ttlSeconds`. A nonce from the current bucket or
 * the previous one is accepted, so a client that received a nonce just before
 * the boundary is not refused a moment later; one two buckets old is. Every
 * response carries the current nonce (`DPoP-Nonce`), which is how the client
 * learns of the rotation before its next proof.
 */
export interface DPoPNonceIssuer {
	/** The nonce for right now. */
	issue(): string;
	/** Whether `nonce` is one this server issued within the acceptance window. */
	verify(nonce: string): boolean;
}

export interface DPoPNonceIssuerOptions {
	/** Shared by every replica. At least 32 bytes. */
	readonly secret: string | Uint8Array;
	/** How often the nonce rotates; the acceptance window is twice this. Default 300 s. */
	readonly ttlSeconds?: number;
	/** Test seam. */
	readonly now?: () => number;
}

export const DEFAULT_DPOP_NONCE_TTL_SECONDS = 300;
const MIN_SECRET_BYTES = 32;

export function createDPoPNonceIssuer(options: DPoPNonceIssuerOptions): DPoPNonceIssuer {
	const secret =
		typeof options.secret === "string" ? new TextEncoder().encode(options.secret) : options.secret;
	if (secret.byteLength < MIN_SECRET_BYTES) {
		throw new Error(
			`createDPoPNonceIssuer: secret must be at least ${MIN_SECRET_BYTES} bytes — a nonce is only ` +
				"as unforgeable as the key that signs it.",
		);
	}
	const ttlSeconds = options.ttlSeconds ?? DEFAULT_DPOP_NONCE_TTL_SECONDS;
	if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0) {
		throw new Error("createDPoPNonceIssuer: ttlSeconds must be a positive integer");
	}
	const now = options.now ?? Date.now;

	const bucketNow = (): number => Math.floor(now() / 1000 / ttlSeconds);
	const macOf = (bucket: number): Buffer =>
		createHmac("sha256", secret).update(`dpop-nonce:${bucket}`).digest();
	const encode = (bucket: number): string => `${bucket}.${macOf(bucket).toString("base64url")}`;

	return {
		issue: () => encode(bucketNow()),
		verify: (nonce) => {
			const dot = nonce.indexOf(".");
			if (dot <= 0) return false;
			const bucket = Number(nonce.slice(0, dot));
			if (!Number.isInteger(bucket)) return false;
			const current = bucketNow();
			if (bucket !== current && bucket !== current - 1) return false;
			const presented = Buffer.from(nonce.slice(dot + 1), "base64url");
			const expected = macOf(bucket);
			return presented.length === expected.length && timingSafeEqual(presented, expected);
		},
	};
}
