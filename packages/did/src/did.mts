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
import { detectAlgorithm } from "./verifiers/detect.mjs";
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

	// Resolve supportedAlgorithms with backward-compatible alias for the old `algorithm` field.
	const rawSupported = didConfig?.supportedAlgorithms as string[] | undefined;
	const rawAlgorithm = didConfig?.algorithm as string | undefined;
	const supportedAlgorithms: string[] =
		rawSupported ??
		(rawAlgorithm ? [rawAlgorithm] : [DEFAULT_ALGORITHM]);

	// Validate all configured algorithms are registered
	for (const alg of supportedAlgorithms) {
		if (!verifierRegistry.has(alg)) {
			throw new Error(
				`Invalid DID grant algorithm: "${alg}". Supported: ${verifierRegistry.algorithms().join(", ")}`,
			);
		}
	}

	// In-memory nonce store (PoC)
	const nonceStore = new Map<string, number>();

	const cleanupInterval = setInterval(() => {
		const now = Date.now();
		for (const [key, time] of nonceStore) {
			if (now - time > messageMaxAgeMs) nonceStore.delete(key);
		}
	}, 60 * 1000);

	// Per-algorithm verifier cache: created lazily on first use
	const verifierCache = new Map<string, SignatureVerifier>();
	const verifierErrorCache = new Map<string, Error>();

	const getVerifier = async (algorithm: string): Promise<SignatureVerifier> => {
		const cached = verifierCache.get(algorithm);
		if (cached) return cached;

		const cachedError = verifierErrorCache.get(algorithm);
		if (cachedError) throw cachedError;

		try {
			const factory = verifierRegistry.get(algorithm);
			if (!factory) throw new Error(`Algorithm "${algorithm}" not registered`);
			const v = await factory(deps.pathResolver);
			verifierCache.set(algorithm, v);
			return v;
		} catch (err) {
			const error = err instanceof Error ? err : new Error(String(err));
			verifierErrorCache.set(algorithm, error);
			throw error;
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

			// 4. Detect algorithm from request body and validate it is allowed
			const detectedAlgorithm = detectAlgorithm(body as Record<string, unknown>);
			if (!detectedAlgorithm) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "unable to detect signature algorithm from request body",
					},
				};
			}
			if (!supportedAlgorithms.includes(detectedAlgorithm)) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: `algorithm "${detectedAlgorithm}" is not supported by this server`,
					},
				};
			}

			// 5. Get (or lazily create) the verifier for the detected algorithm
			// Note: nonce/timestamp checks happen after verification because the verifier
			// owns message parsing (format-specific). Trade-off: replay requests pay crypto
			// cost before rejection. Acceptable for PoC in-memory nonce store.
			let v: SignatureVerifier;
			try {
				v = await getVerifier(detectedAlgorithm);
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

			// 6. Validate nonce and timestamp presence
			if (!parsedMessage.nonce || !parsedMessage.timestamp) {
				return {
					result: {
						status: 400,
						error: "invalid_request",
						errorDescription: "message must include nonce and timestamp",
					},
				};
			}

			// 7. Validate timestamp freshness
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

			// 8. Nonce replay check
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

			// 9. Validate audience against allowlist (empty allowlist = any audience accepted)
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

			// 10. Store nonce (only after ALL validations passed)
			nonceStore.set(nonceKey, Date.now());

			// 11. Generate token
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
