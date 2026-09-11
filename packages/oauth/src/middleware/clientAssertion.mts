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
	consoleLogger,
	type Logger,
	type PublicClient,
	type ReplaySeenSet,
} from "@o3co/auth-provider-core";
import {
	createLocalJWKSet,
	createRemoteJWKSet,
	customFetch,
	decodeJwt,
	errors,
	type JSONWebKeySet,
	type JWTPayload,
	type JWTVerifyGetKey,
	jwtVerify,
} from "jose";

/**
 * `private_key_jwt` client authentication (RFC 7523 §2.2 / OIDC Core §9, #484).
 *
 * A confidential client proves it is who it says by signing a short-lived
 * JWT with its own private key; the provider verifies it under the public
 * keys the client registered (`jwks`) or publishes (`jwksUri`). Nothing
 * shared has to be distributed to the client's replicas or rotated
 * everywhere at once, and every assertion carries a `jti` that is spent
 * exactly once.
 *
 * This verifier is the whole of the trust decision — which client the
 * assertion names, whose keys it must verify under, what the claims must
 * say, and that the `jti` is fresh. The middleware around it only decides
 * how to answer, and that no second method rides along on the request.
 */
export const JWT_BEARER_CLIENT_ASSERTION_TYPE =
	"urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/**
 * The JWS algorithms an assertion may be signed with: asymmetric only. A
 * shared secret is exactly what this method exists to avoid, and `none` is
 * never a signature.
 */
export const CLIENT_ASSERTION_ALGORITHMS = [
	"RS256",
	"RS384",
	"RS512",
	"PS256",
	"PS384",
	"PS512",
	"ES256",
	"ES384",
	"ES512",
	"EdDSA",
] as const;

/**
 * How far ahead `exp` may be. RFC 7523 requires `exp` but bounds nothing;
 * client libraries mint assertions that live a minute or ten, and an hour
 * leaves room for a client whose clock runs ahead while keeping the
 * replay record — which lives until `exp` — small.
 */
export const MAX_CLIENT_ASSERTION_LIFETIME_SECONDS = 3600;

/** The replay-record scope is per client: `client-assertion:<client_id>`. */
export const CLIENT_ASSERTION_REPLAY_SCOPE_PREFIX = "client-assertion:";

export interface ClientAssertionVerifierOptions {
	/** The issuer identifier — accepted as `aud` (RFC 7523 §3). */
	readonly issuer?: string;
	/** The absolute token endpoint URL — also accepted as `aud`. */
	readonly tokenEndpoint?: string;
	/** Where `jti` values are spent. Absent → assertions are answered `server_error`. */
	readonly replaySeenSet?: ReplaySeenSet;
	readonly logger?: Logger;
	/** Clock tolerance on `exp` / `nbf` / `iat`, in seconds. Default 30. `iat` is also held to the lifetime ceiling. */
	readonly clockToleranceSeconds?: number;
	/** The fetch used for `jwksUri`. A proxy, or a test seam. */
	readonly fetch?: typeof fetch;
	/** Test seam. */
	readonly now?: () => number;
}

export type ClientAssertionOutcome =
	/** No `client_assertion` in the request — the other methods apply. */
	| { readonly kind: "absent" }
	| {
			readonly kind: "refused";
			readonly status: 400 | 401 | 500 | 503;
			readonly error:
				| "invalid_request"
				| "invalid_client"
				| "server_error"
				| "temporarily_unavailable";
			readonly description?: string;
	  }
	| { readonly kind: "ok"; readonly client: PublicClient };

export interface ClientAssertionVerifier {
	verify(
		body: Record<string, unknown> | undefined,
		findClient: (clientId: string) => Promise<PublicClient | null>,
	): Promise<ClientAssertionOutcome>;
}

/** Whether the request carries either half of a client assertion. */
export const hasClientAssertion = (body: Record<string, unknown> | undefined): boolean =>
	body !== undefined &&
	(body.client_assertion !== undefined || body.client_assertion_type !== undefined);

const JWKS_TIMEOUT_MS = 5_000;
const JWKS_COOLDOWN_MS = 30_000;
const JWKS_CACHE_MAX_AGE_MS = 600_000;

export function createClientAssertionVerifier(
	options: ClientAssertionVerifierOptions,
): ClientAssertionVerifier {
	const logger = options.logger ?? consoleLogger;
	const clockTolerance = options.clockToleranceSeconds ?? 30;
	const now = options.now ?? Date.now;
	const audiences = [options.issuer, options.tokenEndpoint].filter(
		(value): value is string => typeof value === "string" && value.length > 0,
	);
	// One remote key set per `jwksUri`: jose caches the document, refetches
	// on an unknown `kid` (with a cooldown, so a flood of bad kids is not a
	// flood of fetches) and refreshes it after `cacheMaxAge`.
	const remoteKeySets = new Map<string, JWTVerifyGetKey>();

	const keySetFor = (client: PublicClient): JWTVerifyGetKey | undefined => {
		if (client.jwks !== undefined) {
			return createLocalJWKSet(client.jwks as unknown as JSONWebKeySet);
		}
		if (typeof client.jwksUri === "string" && client.jwksUri.length > 0) {
			let set = remoteKeySets.get(client.jwksUri);
			if (!set) {
				set = createRemoteJWKSet(new URL(client.jwksUri), {
					timeoutDuration: JWKS_TIMEOUT_MS,
					cooldownDuration: JWKS_COOLDOWN_MS,
					cacheMaxAge: JWKS_CACHE_MAX_AGE_MS,
					...(options.fetch ? { [customFetch]: options.fetch } : {}),
				});
				remoteKeySets.set(client.jwksUri, set);
			}
			return set;
		}
		return undefined;
	};

	const refuse = (
		status: 400 | 401 | 500 | 503,
		error: "invalid_request" | "invalid_client" | "server_error" | "temporarily_unavailable",
		description: string,
		reason: string,
		context: Record<string, unknown> = {},
	): ClientAssertionOutcome => {
		const log = status >= 500 ? logger.error.bind(logger) : logger.warn.bind(logger);
		log({ reason, ...context }, "client_assertion_refused");
		return { kind: "refused", status, error, description };
	};

	return {
		async verify(body, findClient) {
			const assertionType = body?.client_assertion_type;
			const assertion = body?.client_assertion;
			if (assertion === undefined && assertionType === undefined) return { kind: "absent" };
			if (
				typeof assertion !== "string" ||
				assertion.length === 0 ||
				typeof assertionType !== "string"
			) {
				return refuse(
					400,
					"invalid_request",
					"client_assertion and client_assertion_type are required together",
					"half_present",
				);
			}
			if (assertionType !== JWT_BEARER_CLIENT_ASSERTION_TYPE) {
				return refuse(
					401,
					"invalid_client",
					`Unsupported client_assertion_type; only ${JWT_BEARER_CLIENT_ASSERTION_TYPE} is accepted`,
					"unsupported_type",
					{ assertionType },
				);
			}
			if (audiences.length === 0) {
				return refuse(
					500,
					"server_error",
					"private_key_jwt client authentication needs a configured issuer to check the assertion audience against",
					"no_audience",
				);
			}

			// Who the assertion says it is, read unverified: the client id
			// selects the keys, so it has to come first. Nothing is trusted
			// until jwtVerify below binds these same claims to a signature.
			let unverified: JWTPayload;
			try {
				unverified = decodeJwt(assertion);
			} catch {
				return refuse(401, "invalid_client", "Invalid client assertion", "malformed");
			}
			const iss = unverified.iss;
			if (typeof iss !== "string" || iss.length === 0 || unverified.sub !== iss) {
				return refuse(
					401,
					"invalid_client",
					"client assertion iss and sub must both be the client_id (RFC 7523 §3)",
					"iss_sub_mismatch",
				);
			}
			const bodyClientId = body?.client_id;
			if (bodyClientId !== undefined && bodyClientId !== iss) {
				return refuse(
					401,
					"invalid_client",
					"client_id does not match the client assertion",
					"client_id_mismatch",
					{ clientId: iss },
				);
			}

			let client: PublicClient | null;
			try {
				client = await findClient(iss);
			} catch (err) {
				// Fail closed, as the secret-based path does.
				return refuse(401, "invalid_client", "Client lookup failed", "lookup_failed", {
					err,
					clientId: iss,
				});
			}
			if (!client) {
				return refuse(401, "invalid_client", "Unknown client", "unknown_client", { clientId: iss });
			}
			if (client.tokenEndpointAuthMethod !== "private_key_jwt") {
				return refuse(
					401,
					"invalid_client",
					`tokenEndpointAuthMethod mismatch: client is configured for "${client.tokenEndpointAuthMethod}"`,
					"method_mismatch",
					{ clientId: iss },
				);
			}

			let keys: JWTVerifyGetKey | undefined;
			try {
				keys = keySetFor(client);
			} catch (err) {
				keys = undefined;
				logger.error({ err, clientId: iss }, "client_assertion_jwks_uri_invalid");
			}
			if (!keys) {
				return refuse(
					500,
					"server_error",
					"client registration carries no usable keys for private_key_jwt",
					"no_keys",
					{ clientId: iss },
				);
			}

			let payload: JWTPayload;
			try {
				({ payload } = await jwtVerify(assertion, keys, {
					issuer: iss,
					subject: iss,
					audience: audiences,
					algorithms: [...CLIENT_ASSERTION_ALGORITHMS],
					clockTolerance,
					// RFC 7523 §3: `exp` is mandatory; jose validates it only when
					// present. `jti` is what makes the assertion single-use.
					requiredClaims: ["exp", "jti"],
				}));
			} catch (err) {
				// A bad signature, a wrong audience, an expired token and an
				// unreachable jwks_uri all answer the same way to the client —
				// the reason goes to the log, where an operator can tell them
				// apart — so a probe learns nothing from the difference.
				const reason = err instanceof errors.JOSEError ? err.code : "jwks_unavailable";
				return refuse(401, "invalid_client", "Invalid client assertion", reason, {
					err,
					clientId: iss,
				});
			}

			const nowSeconds = Math.floor(now() / 1000);
			const exp = payload.exp as number;
			if (exp - nowSeconds > MAX_CLIENT_ASSERTION_LIFETIME_SECONDS) {
				return refuse(
					401,
					"invalid_client",
					`client assertion exp is too far ahead (at most ${MAX_CLIENT_ASSERTION_LIFETIME_SECONDS} seconds)`,
					"lifetime",
					{ clientId: iss },
				);
			}
			// RFC 7523 §3 (6): `iat`, when present, must not be unreasonably far in
			// the past — and a client whose clock runs ahead of ours beyond the
			// tolerance is refused too, since jose checks the claim's type only.
			// The ceiling for age is the same one `exp` is held to.
			const iat = payload.iat;
			if (iat !== undefined) {
				if (iat - nowSeconds > clockTolerance) {
					return refuse(
						401,
						"invalid_client",
						"client assertion iat is in the future",
						"iat_future",
						{ clientId: iss },
					);
				}
				if (nowSeconds - iat > MAX_CLIENT_ASSERTION_LIFETIME_SECONDS + clockTolerance) {
					return refuse(
						401,
						"invalid_client",
						`client assertion iat is too old (at most ${MAX_CLIENT_ASSERTION_LIFETIME_SECONDS} seconds)`,
						"iat_stale",
						{ clientId: iss },
					);
				}
			}
			const jti = payload.jti;
			if (typeof jti !== "string" || jti.length === 0) {
				return refuse(
					401,
					"invalid_client",
					"client assertion jti must be a non-empty string",
					"jti_shape",
					{ clientId: iss },
				);
			}

			// The jti is spent last, once everything else has been proven: a
			// refused assertion must not burn a jti that was never usable, and
			// an accepted one must never be usable twice.
			if (!options.replaySeenSet) {
				return refuse(
					500,
					"server_error",
					"private_key_jwt client authentication needs a replaySeenSet to record each assertion's jti; none is wired",
					"replay_store_missing",
					{ clientId: iss },
				);
			}
			let fresh: boolean;
			try {
				// Kept until the assertion itself expires (plus the tolerance it
				// was accepted with), which is exactly how long it could be replayed.
				fresh = await options.replaySeenSet.markSeen(
					`${CLIENT_ASSERTION_REPLAY_SCOPE_PREFIX}${iss}`,
					jti,
					(exp + clockTolerance) * 1000,
				);
			} catch (err) {
				return refuse(
					503,
					"temporarily_unavailable",
					"Client authentication is temporarily unavailable",
					"replay_store_unavailable",
					{ err, clientId: iss },
				);
			}
			if (!fresh) {
				return refuse(
					401,
					"invalid_client",
					"client assertion jti has already been used",
					"replay",
					{ clientId: iss },
				);
			}

			return { kind: "ok", client };
		},
	};
}
