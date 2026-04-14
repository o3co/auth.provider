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
import { compactVerify, decodeProtectedHeader, importJWK } from "jose";

import type {
	ParsedMessage,
	SignatureVerifier,
	VerificationContext,
	VerificationResult,
} from "./types.mjs";

type JwsAlgorithm = "EdDSA" | "ES256" | "ES256K";

export class JwsVerifier implements SignatureVerifier {
	constructor(private readonly expectedAlg: JwsAlgorithm) {}

	async verify(ctx: VerificationContext): Promise<VerificationResult> {
		const { body, did, resolvedKey } = ctx;

		// 1. Validate jws is present
		if (typeof body.jws !== "string" || !body.jws) {
			return {
				valid: false,
				error: "invalid_request",
				errorDescription: "jws is required",
			};
		}

		// 2. Decode protected header and check algorithm
		let header: { alg?: string };
		try {
			header = decodeProtectedHeader(body.jws);
		} catch {
			return {
				valid: false,
				error: "invalid_request",
				errorDescription: "invalid JWS protected header",
			};
		}

		if (header.alg !== this.expectedAlg) {
			return {
				valid: false,
				error: "invalid_request",
				errorDescription: `algorithm mismatch: expected ${this.expectedAlg}, got ${header.alg}`,
			};
		}

		// 3. Import public key from resolvedKey (JWK format only for JWS)
		if (resolvedKey.format !== "jwk") {
			return {
				valid: false,
				error: "invalid_request",
				errorDescription: "JwsVerifier requires a JWK key; multibase is not supported",
			};
		}
		let publicKey: CryptoKey | Uint8Array;
		try {
			publicKey = await importJWK(resolvedKey.key, this.expectedAlg);
		} catch {
			return {
				valid: false,
				error: "invalid_request",
				errorDescription: "invalid JWK public key",
			};
		}

		// 5. Verify JWS signature
		let payload: Uint8Array;
		try {
			const result = await compactVerify(body.jws, publicKey);
			payload = result.payload;
		} catch {
			return {
				valid: false,
				error: "invalid_grant",
				errorDescription: "JWS signature verification failed",
			};
		}

		// 6. Parse payload as JSON -> ParsedMessage
		let parsedMessage: ParsedMessage;
		try {
			parsedMessage = JSON.parse(new TextDecoder().decode(payload)) as ParsedMessage;
		} catch {
			return {
				valid: false,
				error: "invalid_request",
				errorDescription: "payload must be valid JSON",
			};
		}

		// 7. Validate payload.did matches ctx.did
		if (parsedMessage.did !== did) {
			return {
				valid: false,
				error: "invalid_request",
				errorDescription: "payload.did must match did",
			};
		}

		// 8. Return success
		return {
			valid: true,
			subject: did,
			audience: parsedMessage.audience,
			parsedMessage,
		};
	}
}
