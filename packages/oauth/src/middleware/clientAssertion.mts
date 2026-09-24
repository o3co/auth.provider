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
	assertionLifetime,
	auditErrorText,
	consoleLogger,
	createRemoteKeySetCache,
	describeInvalidAssertionClockTolerance,
	isValidAssertionClockTolerance,
	isRecordableJti,
	isWellFormedClientId,
	type Logger,
	loggableError,
	MAX_ASSERTION_LIFETIME_SECONDS,
	MAX_JTI_LENGTH,
	malformedNumericDateClaim,
	type PublicClient,
	type ReplaySeenSet,
} from "@o3co/auth-provider-core";
import {
	createLocalJWKSet,
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
 * How far ahead `exp` may be, and how old `iat`: core's
 * `MAX_ASSERTION_LIFETIME_SECONDS`, the one ceiling for every assertion whose
 * `jti` this server records — an ID-JAG is held to it too. RFC 7523 requires
 * `exp` but bounds nothing; client libraries mint assertions that live a
 * minute or ten, and an hour leaves room for a client whose clock runs ahead
 * while keeping the replay record — which lives until `exp` — small. Both
 * limits allow the verifier's clock tolerance on top, as the ID-JAG ceiling
 * does: `exp − now` is compared through core's `assertionLifetime`.
 */
export const MAX_CLIENT_ASSERTION_LIFETIME_SECONDS = MAX_ASSERTION_LIFETIME_SECONDS;

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
	/**
	 * Clock tolerance on `exp` / `nbf` / `iat`, in seconds. Default 30. Also
	 * allowed on top of the lifetime ceiling, both ways: `exp − now` and the
	 * `iat` age may each be at most `MAX_CLIENT_ASSERTION_LIFETIME_SECONDS`
	 * plus this.
	 */
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

export function createClientAssertionVerifier(
	options: ClientAssertionVerifierOptions,
): ClientAssertionVerifier {
	const logger = options.logger ?? consoleLogger;
	const clockTolerance = options.clockToleranceSeconds ?? 30;
	// NaN, Infinity or a string would switch jose's exp check and the
	// lifetime ceiling off.
	if (!isValidAssertionClockTolerance(clockTolerance)) {
		throw new Error(
			`createClientAssertionVerifier: ${describeInvalidAssertionClockTolerance(clockTolerance)}.`,
		);
	}
	const now = options.now ?? Date.now;
	const audiences = [options.issuer, options.tokenEndpoint].filter(
		(value): value is string => typeof value === "string" && value.length > 0,
	);
	// One remote key set per `jwksUri`, shared across requests (core's
	// `createRemoteKeySetCache`, which the trust-registry verifier uses too).
	const remoteKeySets = createRemoteKeySetCache({ fetch: options.fetch });

	const keySetFor = (client: PublicClient): JWTVerifyGetKey | undefined => {
		if (client.jwks !== undefined) {
			return createLocalJWKSet(client.jwks as unknown as JSONWebKeySet);
		}
		if (typeof client.jwksUri === "string" && client.jwksUri.length > 0) {
			return remoteKeySets.keySetFor(client.jwksUri);
		}
		return undefined;
	};

	/**
	 * Log a refusal and say how to answer it. A caught error handed over as
	 * `err` reaches the log as `loggableError(err)`, never as itself: a replay
	 * store's ioredis error carries the refused command's arguments, a client
	 * lookup's library error its own fields, and jose's claim errors the
	 * assertion's claims as `payload`. The context is typed, so nothing else
	 * reaches the log beside the client id and an unsupported assertion type
	 * — and both of those are the client's input, read before any signature
	 * is checked, so they are recorded through `auditErrorText` (sanitised,
	 * capped).
	 */
	const refuse = (
		status: 400 | 401 | 500 | 503,
		error: "invalid_request" | "invalid_client" | "server_error" | "temporarily_unavailable",
		description: string,
		reason: string,
		context: {
			readonly clientId?: string;
			readonly assertionType?: string;
			readonly err?: unknown;
			/** A `lifetime` refusal's numbers: `exp − now` and the most it may be. */
			readonly lifetimeSeconds?: number;
			readonly maxLifetimeSeconds?: number;
		} = {},
	): ClientAssertionOutcome => {
		const log = status >= 500 ? logger.error.bind(logger) : logger.warn.bind(logger);
		const { err, clientId, assertionType, lifetimeSeconds, maxLifetimeSeconds } = context;
		log(
			{
				reason,
				...(clientId !== undefined ? { clientId: auditErrorText(clientId) } : {}),
				...(assertionType !== undefined ? { assertionType: auditErrorText(assertionType) } : {}),
				...(lifetimeSeconds !== undefined ? { lifetimeSeconds, maxLifetimeSeconds } : {}),
				...("err" in context ? { err: loggableError(err) } : {}),
			},
			"client_assertion_refused",
		);
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
					"client assertion iss and sub must both be the client_id (RFC 7523 section 3)",
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
			// An iss no client can have is refused like an unknown one, before
			// the repository is asked — a repository may throw on it, and that
			// would read as the server's outage (core's `isWellFormedClientId`).
			if (!isWellFormedClientId(iss)) {
				return refuse(401, "invalid_client", "Unknown client", "malformed_client_id", {
					clientId: iss,
				});
			}

			let client: PublicClient | null;
			try {
				client = await findClient(iss);
			} catch (err) {
				// Fail closed, as the secret-based path does — as the server's
				// outage, not a failed authentication: the client did nothing
				// wrong, and `invalid_client` would tell it its credential is bad.
				return refuse(
					503,
					"temporarily_unavailable",
					"client repository unavailable",
					"client_repository_unavailable",
					{ err, clientId: iss },
				);
			}
			if (!client) {
				return refuse(401, "invalid_client", "Unknown client", "unknown_client", { clientId: iss });
			}
			if (client.tokenEndpointAuthMethod !== "private_key_jwt") {
				return refuse(
					401,
					"invalid_client",
					`tokenEndpointAuthMethod mismatch: client is configured for '${client.tokenEndpointAuthMethod}'`,
					"method_mismatch",
					{ clientId: iss },
				);
			}

			let keys: JWTVerifyGetKey | undefined;
			try {
				keys = keySetFor(client);
			} catch (err) {
				keys = undefined;
				logger.error(
					{ err: loggableError(err), clientId: iss },
					"client_assertion_jwks_uri_invalid",
				);
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

			// `exp`, `iat` and `nbf` are NumericDates before anything below
			// computes a lifetime or an age from them (core's
			// `isNumericDate`): jose checks only that each is a number, and
			// JSON's `1e400` parses to Infinity. The checks below happened to
			// refuse an infinite `exp` or `iat` under reasons that describe a
			// finite one, and let an infinite `nbf` through.
			const malformedDate = malformedNumericDateClaim(payload);
			if (malformedDate !== undefined) {
				return refuse(
					401,
					"invalid_client",
					`client assertion ${malformedDate} is not a NumericDate (RFC 7519 section 2)`,
					"numeric_date",
					{ clientId: iss },
				);
			}

			const nowSeconds = Math.floor(now() / 1000);
			const exp = payload.exp as number;
			// The ceiling the ID-JAG verifier holds its assertions to, with the
			// same allowance for a client whose clock runs ahead.
			const lifetime = assertionLifetime(exp, nowSeconds, clockTolerance);
			if (lifetime.exceeded) {
				return refuse(
					401,
					"invalid_client",
					`client assertion exp is too far ahead (at most ${MAX_CLIENT_ASSERTION_LIFETIME_SECONDS} seconds)`,
					"lifetime",
					{
						clientId: iss,
						lifetimeSeconds: lifetime.lifetimeSeconds,
						maxLifetimeSeconds: lifetime.maxLifetimeSeconds,
					},
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
			// Bounded (`MAX_JTI_LENGTH`) as well as present: the jti is a seen-set
			// key kept until the assertion expires, and the client chooses it.
			const jti = payload.jti;
			if (!isRecordableJti(jti)) {
				return refuse(
					401,
					"invalid_client",
					`client assertion jti must be a non-empty string of at most ${MAX_JTI_LENGTH} characters`,
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
