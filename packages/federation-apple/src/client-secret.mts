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

import { importPKCS8, SignJWT } from "jose";

/** The `aud` Apple requires on a client-secret assertion. */
export const APPLE_AUDIENCE = "https://appleid.apple.com";

/**
 * Apple's documented ceiling on `exp - iat` for a client secret: six months,
 * to the second. A longer-lived assertion is rejected at the token endpoint.
 */
export const APPLE_CLIENT_SECRET_MAX_LIFETIME_SECONDS = 15_777_000;

/**
 * 180 days — deliberately short of the ceiling rather than exactly on it.
 * Signing at the maximum leaves nothing for clock skew between this process
 * and Apple's, and turns a boundary comparison at the token endpoint into a
 * production outage; 180 days costs one extra signature every six months.
 */
export const APPLE_CLIENT_SECRET_DEFAULT_LIFETIME_SECONDS = 180 * 24 * 60 * 60;

/**
 * How close to `exp` a cached secret may get before it is re-signed.
 *
 * A day is long enough that no token exchange can be holding a secret that
 * expires mid-flight, and short enough that the signature is computed roughly
 * once per lifetime rather than once per request.
 */
export const APPLE_CLIENT_SECRET_RENEWAL_WINDOW_SECONDS = 86_400;

export interface AppleClientSecretOptions {
	/** Apple Developer Team ID — the assertion's `iss`. */
	readonly teamId: string;
	/** Services ID — the assertion's `sub`, and the OAuth `client_id`. */
	readonly clientId: string;
	/** Key ID of the downloaded `.p8`, carried in the JWT header as `kid`. */
	readonly keyId: string;
	/**
	 * The `.p8` private key, PKCS#8 PEM, exactly as downloaded
	 * (`-----BEGIN PRIVATE KEY-----` … ). Read at signing time rather than
	 * captured at construction, so a deployment whose mounted key is repaired
	 * or rotated under it recovers without a restart.
	 */
	readonly privateKey: string;
	/** Defaults to {@link APPLE_CLIENT_SECRET_DEFAULT_LIFETIME_SECONDS}. */
	readonly lifetimeSeconds?: number;
	/** Clock, in milliseconds. Test seam; defaults to `Date.now`. */
	readonly now?: () => number;
}

const requireNonEmpty = (value: unknown, field: string): string => {
	if (typeof value !== "string" || value.length === 0) {
		throw new Error(`Apple client secret requires a non-empty ${field}`);
	}
	return value;
};

/**
 * Build the resolver for Apple's `client_secret`: an ES256 JWT this relying
 * party signs with the `.p8` key it downloaded from the Apple Developer
 * portal.
 *
 * Apple is the only IdP in this repo whose client secret is not a string a
 * config file can hold. The assertion is:
 *
 * ```text
 * header  { alg: "ES256", kid: <Key ID> }
 * payload { iss: <Team ID>, sub: <Services ID>, aud: "https://appleid.apple.com",
 *           iat: <now>, exp: <now + lifetime ≤ 6 months> }
 * ```
 *
 * The returned function is the `FederationClientSecret` callable form the
 * session package resolves per token exchange. It caches the signed JWT and
 * re-signs only once the cached one comes within
 * {@link APPLE_CLIENT_SECRET_RENEWAL_WINDOW_SECONDS} of `exp` — the framework
 * deliberately does not cache, because only this module knows when its secret
 * expires.
 *
 * Concurrent callers share one in-flight signature rather than each starting
 * their own, and a failed signature leaves the cache untouched so the next
 * call retries instead of inheriting a poisoned entry.
 *
 * Validation is at construction where it can be (a boot-time misconfiguration
 * should fail at boot) and at signing where it must be (the key material is
 * read late by design).
 */
export function createAppleClientSecret(options: AppleClientSecretOptions): () => Promise<string> {
	const teamId = requireNonEmpty(options.teamId, "teamId");
	const clientId = requireNonEmpty(options.clientId, "clientId");
	const keyId = requireNonEmpty(options.keyId, "keyId");
	requireNonEmpty(options.privateKey, "privateKey");

	const lifetimeSeconds = options.lifetimeSeconds ?? APPLE_CLIENT_SECRET_DEFAULT_LIFETIME_SECONDS;
	if (!Number.isFinite(lifetimeSeconds) || lifetimeSeconds <= 0) {
		throw new Error(`Apple client secret lifetime must be a positive number of seconds`);
	}
	if (lifetimeSeconds > APPLE_CLIENT_SECRET_MAX_LIFETIME_SECONDS) {
		throw new Error(
			`Apple client secret lifetime must not exceed six months (${APPLE_CLIENT_SECRET_MAX_LIFETIME_SECONDS}s); Apple rejects a longer-lived assertion`,
		);
	}

	const now = options.now ?? Date.now;

	let signingKey: Promise<CryptoKey> | undefined;
	const importSigningKey = (): Promise<CryptoKey> => {
		if (!signingKey) {
			signingKey = (importPKCS8(options.privateKey, "ES256") as Promise<CryptoKey>).catch(
				(err: unknown) => {
					// Drop the rejected promise so a later call re-reads the key
					// material rather than replaying this failure forever.
					signingKey = undefined;
					throw err;
				},
			);
		}
		return signingKey;
	};

	let cached: { readonly jwt: string; readonly expiresAtSeconds: number } | undefined;
	let inFlight: Promise<string> | undefined;

	const sign = async (): Promise<string> => {
		const key = await importSigningKey();
		const issuedAtSeconds = Math.floor(now() / 1000);
		const expiresAtSeconds = issuedAtSeconds + lifetimeSeconds;
		const jwt = await new SignJWT({})
			.setProtectedHeader({ alg: "ES256", kid: keyId })
			.setIssuer(teamId)
			.setSubject(clientId)
			.setAudience(APPLE_AUDIENCE)
			.setIssuedAt(issuedAtSeconds)
			.setExpirationTime(expiresAtSeconds)
			.sign(key);
		cached = { jwt, expiresAtSeconds };
		return jwt;
	};

	return async (): Promise<string> => {
		const nowSeconds = Math.floor(now() / 1000);
		if (
			cached &&
			nowSeconds < cached.expiresAtSeconds - APPLE_CLIENT_SECRET_RENEWAL_WINDOW_SECONDS
		) {
			return cached.jwt;
		}
		if (!inFlight) {
			inFlight = sign().finally(() => {
				inFlight = undefined;
			});
		}
		return inFlight;
	};
}
