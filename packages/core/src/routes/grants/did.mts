/*
 * Copyright 2026 1o1 Inc.
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

import { formatObject, generateToken, generateTokenResponse } from "./token.mjs";
import type { GrantContext, GrantDependencies, GrantHandler } from "./types.mjs";

export const createDidGrant = (deps: GrantDependencies): GrantHandler => {
	const { config } = deps;
	const messageMaxAgeMs = config.oauth.grants.did.messageMaxAgeSec * 1000;

	// In-memory nonce store (PoC)
	// Production: use Redis with TTL
	const nonceStore = new Map<string, number>();

	const cleanupInterval = setInterval(() => {
		const now = Date.now();
		for (const [key, time] of nonceStore) {
			if (now - time > messageMaxAgeMs) nonceStore.delete(key);
		}
	}, 60 * 1000);

	return {
		async handle({ req, res, issuer }: GrantContext): Promise<void> {
			const { did, signature, message: signedMessage, publicKey } = req.body;

			// 1. Validate required fields
			if (!did || !signature || !signedMessage) {
				res.status(400).json({
					error: "invalid_request",
					error_description: "did, signature, and message are required",
				});
				return;
			}

			// 2. Parse message JSON
			let parsedMessage: {
				did: string;
				timestamp: string;
				nonce: string;
				audience?: string;
			};
			try {
				parsedMessage = JSON.parse(signedMessage);
			} catch {
				res.status(400).json({
					error: "invalid_request",
					error_description: "message must be valid JSON",
				});
				return;
			}

			// 3. Validate message.did matches top-level did
			if (parsedMessage.did !== did) {
				res.status(400).json({
					error: "invalid_request",
					error_description: "message.did must match did",
				});
				return;
			}

			// 4. Validate nonce and timestamp presence
			if (!parsedMessage.nonce || !parsedMessage.timestamp) {
				res.status(400).json({
					error: "invalid_request",
					error_description: "message must include nonce and timestamp",
				});
				return;
			}

			// 5. Validate timestamp (within configurable max age)
			const messageTime = new Date(parsedMessage.timestamp).getTime();
			const now = Date.now();
			if (Number.isNaN(messageTime) || Math.abs(now - messageTime) > messageMaxAgeMs) {
				res.status(400).json({
					error: "invalid_request",
					error_description: "message timestamp is expired or invalid",
				});
				return;
			}

			// 6. Nonce replay check (before signature verification — reject cheaply)
			const nonceKey = `did-nonce:${parsedMessage.nonce}`;
			if (nonceStore.has(nonceKey)) {
				res.status(400).json({
					error: "invalid_request",
					error_description: "nonce already used",
				});
				return;
			}

			// 7. Verify Ed25519 signature
			// PoC: publicKey provided directly in request body
			// Production: resolve from DID Document via Registry
			if (!publicKey) {
				res.status(400).json({
					error: "invalid_request",
					error_description:
						"publicKey is required (PoC: provide directly, production: resolve from DID Document)",
				});
				return;
			}

			try {
				const signatureBytes = Buffer.from(signature, "base64");
				const messageBytes = new TextEncoder().encode(signedMessage);
				const publicKeyBytes = Buffer.from(publicKey, "base64");

				const valid = await verifyAsync(signatureBytes, messageBytes, publicKeyBytes);
				if (!valid) {
					res.status(401).json({
						error: "invalid_grant",
						error_description: "DID signature verification failed",
					});
					return;
				}
			} catch {
				res.status(401).json({
					error: "invalid_grant",
					error_description: "DID signature verification error",
				});
				return;
			}

			// 8. Store nonce (only after signature is verified)
			nonceStore.set(nonceKey, Date.now());

			// 9. Generate token (M2M: access token only, no refresh token)
			const didPayload = formatObject({
				did,
				ip: req.ip,
			});

			res.status(200).json(
				generateTokenResponse({
					accessToken: generateToken(didPayload, {
						expiresIn: config.oauth.accessToken.expiresIn,
						secret: config.oauth.jwt.secret,
						issuer,
						type: "access",
						audience: parsedMessage.audience,
					}),
				}),
			);
		},

		cleanup(): void {
			clearInterval(cleanupInterval);
		},
	};
};
