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
import { verifyAsync } from "@noble/ed25519";

import type { ParsedMessage, SignatureVerifier, VerificationContext, VerificationResult } from "./types.mjs";

export class Ed25519RawVerifier implements SignatureVerifier {
	async verify(ctx: VerificationContext): Promise<VerificationResult> {
		const { body, did } = ctx;

		// 1. Validate signature and message are present
		if (typeof body.signature !== "string" || !body.signature) {
			return {
				valid: false,
				error: "invalid_request",
				errorDescription: "signature is required",
			};
		}
		if (typeof body.message !== "string" || !body.message) {
			return {
				valid: false,
				error: "invalid_request",
				errorDescription: "message is required",
			};
		}

		// 2. Decode and parse message as JSON
		let messageString: string;
		try {
			messageString = Buffer.from(body.message, "base64").toString("utf-8");
		} catch {
			return {
				valid: false,
				error: "invalid_request",
				errorDescription: "message must be valid base64",
			};
		}

		let parsedMessage: ParsedMessage;
		try {
			parsedMessage = JSON.parse(messageString) as ParsedMessage;
		} catch {
			return {
				valid: false,
				error: "invalid_request",
				errorDescription: "message must be valid JSON",
			};
		}

		// 3. Validate message.did matches ctx.did
		if (parsedMessage.did !== did) {
			return {
				valid: false,
				error: "invalid_request",
				errorDescription: "message.did must match did",
			};
		}

		// 4. Validate publicKey is present
		if (typeof body.publicKey !== "string" || !body.publicKey) {
			return {
				valid: false,
				error: "invalid_request",
				errorDescription: "publicKey is required",
			};
		}

		// 5. Verify Ed25519 signature
		try {
			const signatureBytes = Buffer.from(body.signature, "base64");
			const messageBytes = Buffer.from(body.message, "base64");
			const publicKeyBytes = Buffer.from(body.publicKey, "base64");

			const valid = await verifyAsync(signatureBytes, messageBytes, publicKeyBytes);
			if (!valid) {
				return {
					valid: false,
					error: "invalid_grant",
					errorDescription: "signature verification failed",
				};
			}
		} catch {
			return {
				valid: false,
				error: "invalid_grant",
				errorDescription: "signature verification error",
			};
		}

		// 6. Return success
		return {
			valid: true,
			subject: did,
			audience: parsedMessage.audience,
			parsedMessage,
		};
	}
}
