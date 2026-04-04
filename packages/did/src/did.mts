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
import {
	generateToken,
	generateTokenResponse,
	type GrantContext,
	type GrantDependencies,
	type GrantHandler,
	type GrantHandlerResult,
} from "@o3co/auth-provider-core";
import { createVerifier, type Algorithm } from "./verifiers/index.mjs";
import type { SignatureVerifier } from "./verifiers/types.mjs";

export const createDidGrant = (deps: GrantDependencies): GrantHandler => {
	const { config, keyStore } = deps;

	const DEFAULT_MESSAGE_MAX_AGE_SEC = 300;
	const DEFAULT_ALGORITHM: Algorithm = "ed25519_raw";
	const didConfig = (config.oauth.grants as Record<string, Record<string, unknown> | undefined>).did;
	const messageMaxAgeMs = ((didConfig?.messageMaxAgeSec as number | undefined) ?? DEFAULT_MESSAGE_MAX_AGE_SEC) * 1000;
	const algorithm = (didConfig?.algorithm as Algorithm | undefined) ?? DEFAULT_ALGORITHM;

	// In-memory nonce store (PoC)
	const nonceStore = new Map<string, number>();

	const cleanupInterval = setInterval(() => {
		const now = Date.now();
		for (const [key, time] of nonceStore) {
			if (now - time > messageMaxAgeMs) nonceStore.delete(key);
		}
	}, 60 * 1000);

	// Verifier is created lazily on first request (async factory)
	let verifier: SignatureVerifier | undefined;
	let verifierError: Error | undefined;

	const getVerifier = async (): Promise<SignatureVerifier> => {
		if (verifierError) throw verifierError;
		if (verifier) return verifier;
		try {
			verifier = await createVerifier(algorithm);
			return verifier;
		} catch (err) {
			verifierError = err instanceof Error ? err : new Error(String(err));
			throw verifierError;
		}
	};

	return {
		async handle(ctx: GrantContext): Promise<GrantHandlerResult> {
			const { body, issuer } = ctx;
			const did = body.did as string | undefined;

			// 1. Validate DID presence
			if (!did) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "did is required",
					},
				};
			}

			// 2. Verify signature via strategy
			let v: SignatureVerifier;
			try {
				v = await getVerifier();
			} catch (err) {
				return {
					result: {
						status: 500,
						error: "server_error",
						errorDescription: err instanceof Error ? err.message : "verifier initialization failed",
					},
				};
			}

			const verification = await v.verify({ body, did });
			if (!verification.valid) {
				const status = verification.error === "invalid_grant" ? 401 : 400;
				return {
					result: {
						status,
						error: verification.error,
						errorDescription: verification.errorDescription,
					},
				};
			}

			const { parsedMessage } = verification;

			// 3. Validate nonce and timestamp presence
			if (!parsedMessage.nonce || !parsedMessage.timestamp) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "message must include nonce and timestamp",
					},
				};
			}

			// 4. Validate timestamp freshness
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

			// 5. Nonce replay check
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

			// 6. Store nonce (only after verification passed)
			nonceStore.set(nonceKey, Date.now());

			// 7. Generate token
			return {
				result: {
					status: 200,
					tokens: generateTokenResponse({
						accessToken: await generateToken({}, {
							expiresIn: config.oauth.accessToken.expiresIn,
							keyStore,
							issuer,
							subject: verification.subject,
							authorizedParty: verification.audience ?? null,
							tokenType: "at+jwt",
							audience: verification.audience,
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
