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

import {
	generateToken,
	generateTokenResponse,
	type GrantContext,
	type GrantDependencies,
	type GrantHandler,
	type GrantHandlerResult,
} from "@o3co/auth-provider-core";

export const createDidGrant = (deps: GrantDependencies): GrantHandler => {
	const { config, keyStore } = deps;
	const didConfig = (config.oauth.grants as Record<string, unknown>).did as
		| { messageMaxAgeSec: number }
		| undefined;
	if (!didConfig) {
		throw new Error(
			"DID grant requires oauth.grants.did config block (with messageMaxAgeSec)",
		);
	}
	const messageMaxAgeMs = didConfig.messageMaxAgeSec * 1000;

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
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const { body, issuer } = ctx;
			const {
				did,
				signature,
				message: signedMessage,
				publicKey,
			} = body as {
				did?: string;
				signature?: string;
				message?: string;
				publicKey?: string;
			};

			// 1. Validate required fields
			if (!did || !signature || !signedMessage) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "did, signature, and message are required",
					},
				};
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
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "message must be valid JSON",
					},
				};
			}

			// 3. Validate message.did matches top-level did
			if (parsedMessage.did !== did) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "message.did must match did",
					},
				};
			}

			// 4. Validate nonce and timestamp presence
			if (!parsedMessage.nonce || !parsedMessage.timestamp) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "message must include nonce and timestamp",
					},
				};
			}

			// 5. Validate timestamp (within configurable max age)
			const messageTime = new Date(parsedMessage.timestamp).getTime();
			const now = Date.now();
			if (Number.isNaN(messageTime) || Math.abs(now - messageTime) > messageMaxAgeMs) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "message timestamp is expired or invalid",
					},
				};
			}

			// 6. Nonce replay check (before signature verification — reject cheaply)
			const nonceKey = `did-nonce:${parsedMessage.nonce}`;
			if (nonceStore.has(nonceKey)) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "nonce already used",
					},
				};
			}

			// 7. Verify Ed25519 signature
			// PoC: publicKey provided directly in request body
			// Production: resolve from DID Document via Registry
			if (!publicKey) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription:
							"publicKey is required (PoC: provide directly, production: resolve from DID Document)",
					},
				};
			}

			try {
				const signatureBytes = Buffer.from(signature, "base64");
				const messageBytes = new TextEncoder().encode(signedMessage);
				const publicKeyBytes = Buffer.from(publicKey, "base64");

				const valid = await verifyAsync(signatureBytes, messageBytes, publicKeyBytes);
				if (!valid) {
					return {
						result: {
							status: 401,
							error: "invalid_grant",
							errorDescription: "DID signature verification failed",
						},
					};
				}
			} catch {
				return {
					result: {
						status: 401,
						error: "invalid_grant",
						errorDescription: "DID signature verification error",
					},
				};
			}

			// 8. Store nonce (only after signature is verified)
			nonceStore.set(nonceKey, Date.now());

			// 9. Generate token (M2M: access token only, no refresh token)
			return {
				result: {
					status: 200,
					tokens: generateTokenResponse({
						accessToken: await generateToken({}, {
							expiresIn: config.oauth.accessToken.expiresIn,
							keyStore,
							issuer,
							subject: did,
							authorizedParty: parsedMessage.audience ?? null,
							tokenType: "at+jwt",
							audience: parsedMessage.audience,
						}),
					}),
				},
			};
		},

		cleanup(): void {
			clearInterval(cleanupInterval);
		},
	};
};
