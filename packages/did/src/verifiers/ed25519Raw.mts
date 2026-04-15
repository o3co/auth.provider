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

import { extractEd25519PublicKeyBytes } from "./ed25519Utils.mjs";
import type {
	ParsedMessage,
	SignatureVerifier,
	VerificationContext,
	VerificationResult,
} from "./types.mjs";

export class Ed25519RawVerifier implements SignatureVerifier {
	private verifyAsync:
		| ((sig: Uint8Array, msg: Uint8Array, pub: Uint8Array) => Promise<boolean>)
		| undefined;
	private pathResolver: PathResolver | undefined;

	constructor(pathResolver?: PathResolver) {
		this.pathResolver = pathResolver;
	}

	private async loadVerifyAsync(): Promise<
		(sig: Uint8Array, msg: Uint8Array, pub: Uint8Array) => Promise<boolean>
	> {
		if (this.verifyAsync) return this.verifyAsync;

		const specifier = "@noble/ed25519";
		const mod = this.pathResolver
			? ((await import(this.pathResolver(specifier))) as {
					verifyAsync: (sig: Uint8Array, msg: Uint8Array, pub: Uint8Array) => Promise<boolean>;
				})
			: ((await import(specifier)) as {
					verifyAsync: (sig: Uint8Array, msg: Uint8Array, pub: Uint8Array) => Promise<boolean>;
				});

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
		return { valid: true, subject: did, audience: parsedMessage.audience, parsedMessage };
	}
}
