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
import { extractVerificationKey } from "./resolver/extractKey.mjs";
import type { DidDocumentResolver } from "./resolver/types.mjs";
import { createDefaultVerifierRegistry } from "./verifiers/factory.mjs";
import type { SignatureVerifier } from "./verifiers/types.mjs";

export interface DidGrantOptions {
	resolver: DidDocumentResolver;
}

export const createDidGrant = (
	deps: GrantDependencies,
	options: DidGrantOptions,
): GrantHandler => {
	const { config, keyStore } = deps;
	const { resolver } = options;

	const DEFAULT_MESSAGE_MAX_AGE_SEC = 300;
	const DEFAULT_ALGORITHM = "ed25519_raw";

	const didConfig = (config.oauth.grants as Record<string, Record<string, unknown> | undefined>).did;
	const messageMaxAgeMs = ((didConfig?.messageMaxAgeSec as number | undefined) ?? DEFAULT_MESSAGE_MAX_AGE_SEC) * 1000;
	const allowedAudiences = (didConfig?.allowedAudiences as string[] | undefined) ?? [];

	const verifierRegistry = createDefaultVerifierRegistry();
	const configuredAlgorithm = didConfig?.algorithm;
	if (configuredAlgorithm !== undefined && !verifierRegistry.has(String(configuredAlgorithm))) {
		throw new Error(
			`Invalid DID grant algorithm: "${String(configuredAlgorithm)}". Supported: ${verifierRegistry.algorithms().join(", ")}`,
		);
	}
	const algorithm = (configuredAlgorithm as string | undefined) ?? DEFAULT_ALGORITHM;

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
			const factory = verifierRegistry.get(algorithm);
			if (!factory) throw new Error(`Algorithm "${algorithm}" not registered`);
			verifier = await factory(deps.pathResolver);
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

			// 2. Resolve DID Document
			let didDocument: Awaited<ReturnType<typeof resolver.resolve>>;
			try {
				didDocument = await resolver.resolve(did);
			} catch (err) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: err instanceof Error ? err.message : "DID resolution failed",
					},
				};
			}

			// 3. Extract verification key from DID Document
			let resolvedKey: Awaited<ReturnType<typeof extractVerificationKey>>;
			try {
				resolvedKey = await extractVerificationKey(didDocument, did);
			} catch (err) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: err instanceof Error ? err.message : "key extraction failed",
					},
				};
			}

			// 4. Verify signature via strategy
			// Note: nonce/timestamp checks happen after verification because the verifier
			// owns message parsing (format-specific). Trade-off: replay requests pay crypto
			// cost before rejection. Acceptable for PoC in-memory nonce store.
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

			const verification = await v.verify({ body, did, resolvedKey });
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

			// 5. Validate nonce and timestamp presence
			if (!parsedMessage.nonce || !parsedMessage.timestamp) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "message must include nonce and timestamp",
					},
				};
			}

			// 6. Validate timestamp freshness
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

			// 7. Nonce replay check
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

			// 8. Validate audience against allowlist (empty allowlist = any audience accepted)
			if (verification.audience && allowedAudiences.length > 0) {
				if (!allowedAudiences.includes(verification.audience)) {
					return {
						result: {
							status: 400,
							error: "invalid_request",
							errorDescription: `audience "${verification.audience}" is not allowed`,
						},
					};
				}
			}

			// 9. Store nonce (only after ALL validations passed)
			nonceStore.set(nonceKey, Date.now());

			// 10. Generate token
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
