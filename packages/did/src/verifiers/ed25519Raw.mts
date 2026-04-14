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
import type { PathResolver } from "@o3co/auth-provider-core";
import type { ExtractedKey } from "../resolver/extractKey.mjs";
import type { ParsedMessage, SignatureVerifier, VerificationContext, VerificationResult } from "./types.mjs";

// Base58btc alphabet (Bitcoin alphabet)
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_MAP: Record<string, number> = {};
for (let i = 0; i < BASE58_ALPHABET.length; i++) {
	BASE58_MAP[BASE58_ALPHABET[i]] = i;
}

function decodeBase58btc(input: string): Uint8Array {
	const bytes = [0];
	for (const char of input) {
		const value = BASE58_MAP[char];
		if (value === undefined) throw new Error(`Invalid base58 character: ${char}`);
		let carry = value;
		for (let i = 0; i < bytes.length; i++) {
			carry += bytes[i] * 58;
			bytes[i] = carry & 0xff;
			carry >>= 8;
		}
		while (carry > 0) {
			bytes.push(carry & 0xff);
			carry >>= 8;
		}
	}
	// Add leading zeros for leading '1's in input
	for (const char of input) {
		if (char === "1") bytes.push(0);
		else break;
	}
	return new Uint8Array(bytes.reverse());
}

/**
 * Extract raw Ed25519 public key bytes from a resolved key.
 *
 * - JWK format: the `x` field is base64url-encoded raw 32-byte key.
 * - Multibase format: base58btc string (prefixed with 'z'), multicodec-prefixed (0xed 0x01).
 */
function extractEd25519PublicKeyBytes(resolvedKey: ExtractedKey): Uint8Array {
	if (resolvedKey.format === "jwk") {
		const jwk = resolvedKey.key;
		if (!jwk.x) throw new Error("JWK is missing x field");
		// base64url decode
		const padded = jwk.x.replace(/-/g, "+").replace(/_/g, "/");
		const base64 = padded.padEnd(padded.length + (4 - (padded.length % 4)) % 4, "=");
		return Uint8Array.from(Buffer.from(base64, "base64"));
	}

	// Multibase: 'z' prefix indicates base58btc encoding
	const multibaseStr = resolvedKey.key;
	if (!multibaseStr.startsWith("z")) {
		throw new Error("Only base58btc multibase ('z' prefix) is supported for Ed25519 keys");
	}
	const decoded = decodeBase58btc(multibaseStr.slice(1));
	// Multicodec prefix for Ed25519 public key is 0xed 0x01
	if (decoded.length < 2 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
		throw new Error("Invalid multicodec prefix for Ed25519 public key");
	}
	return decoded.slice(2);
}

export class Ed25519RawVerifier implements SignatureVerifier {
	private verifyAsync: ((sig: Uint8Array, msg: Uint8Array, pub: Uint8Array) => Promise<boolean>) | undefined;
	private pathResolver: PathResolver | undefined;

	constructor(pathResolver?: PathResolver) {
		this.pathResolver = pathResolver;
	}

	private async loadVerifyAsync(): Promise<(sig: Uint8Array, msg: Uint8Array, pub: Uint8Array) => Promise<boolean>> {
		if (this.verifyAsync) return this.verifyAsync;

		const specifier = "@noble/ed25519";
		const mod = this.pathResolver
			? (await import(this.pathResolver(specifier))) as { verifyAsync: (sig: Uint8Array, msg: Uint8Array, pub: Uint8Array) => Promise<boolean> }
			: (await import(specifier)) as { verifyAsync: (sig: Uint8Array, msg: Uint8Array, pub: Uint8Array) => Promise<boolean> };

		this.verifyAsync = mod.verifyAsync;
		return this.verifyAsync;
	}

	async verify(ctx: VerificationContext): Promise<VerificationResult> {
		const { body, did, resolvedKey } = ctx;

		// 1. Validate signature and message are present
		if (typeof body.signature !== "string" || !body.signature) {
			return { valid: false, error: "invalid_request", errorDescription: "signature is required" };
		}
		if (typeof body.message !== "string" || !body.message) {
			return { valid: false, error: "invalid_request", errorDescription: "message is required" };
		}

		// 2. Parse message as JSON
		let parsedMessage: ParsedMessage;
		try {
			parsedMessage = JSON.parse(body.message) as ParsedMessage;
		} catch {
			return { valid: false, error: "invalid_request", errorDescription: "message must be valid JSON" };
		}

		// 3. Validate message.did matches ctx.did
		if (parsedMessage.did !== did) {
			return { valid: false, error: "invalid_request", errorDescription: "message.did must match did" };
		}

		// 4. Extract public key bytes from resolvedKey
		let publicKeyBytes: Uint8Array;
		try {
			publicKeyBytes = extractEd25519PublicKeyBytes(resolvedKey);
		} catch (err) {
			return {
				valid: false,
				error: "invalid_request",
				errorDescription: err instanceof Error ? err.message : "invalid public key",
			};
		}

		// 5. Verify Ed25519 signature
		try {
			const verifyAsync = await this.loadVerifyAsync();
			const signatureBytes = Buffer.from(body.signature, "base64");
			const messageBytes = new TextEncoder().encode(body.message);

			const valid = await verifyAsync(signatureBytes, messageBytes, publicKeyBytes);
			if (!valid) {
				return { valid: false, error: "invalid_grant", errorDescription: "signature verification failed" };
			}
		} catch {
			return { valid: false, error: "invalid_grant", errorDescription: "signature verification error" };
		}

		// 6. Return success
		return { valid: true, subject: did, audience: parsedMessage.audience, parsedMessage };
	}
}
