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
import { createHash } from "node:crypto";
import type { Request, Response, Router } from "express";
import { exportJWK } from "jose";
import type { KeyStore, ManagedKey } from "../keys/KeyStore.mjs";
import type { EventLogger } from "../logging/Logger.mjs";
import { loggableError } from "../logging/loggableError.mjs";
import { DEFAULT_JWKS_CACHE_MAX_AGE } from "./cache.mjs";
import { DEFAULT_JWKS_PATH, isValidJwksPath } from "./path.mjs";

/**
 * JWK members that carry PRIVATE or SYMMETRIC key material and must never
 * appear in a published JWKS: RSA (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`),
 * EC/OKP (`d`), and symmetric (`k`). Per RFC 7517 §9.3 / RFC 7518.
 */
const PRIVATE_JWK_MEMBERS: readonly string[] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/**
 * Reduces an exported JWK to its public members, or `null` for a symmetric
 * (`kty: "oct"`) key, which has no public form. Defense in depth for custom
 * `KeyStore` adapters: private or symmetric material returned as `publicKey`
 * must never reach the JWKS response.
 */
function toPublicJwk(jwk: Record<string, unknown>): Record<string, unknown> | null {
	if (jwk.kty === "oct") return null;
	const pub: Record<string, unknown> = {};
	for (const [member, value] of Object.entries(jwk)) {
		if (PRIVATE_JWK_MEMBERS.includes(member)) continue;
		pub[member] = value;
	}
	return pub;
}

/** Options for {@link createRouter}. */
export interface JwksRouterOptions {
	/**
	 * Absolute path the router registers internally. Defaults to
	 * {@link DEFAULT_JWKS_PATH}. Callers honoring `jwks.path` resolve it via
	 * `resolveJwksPath` and pass the result here so the registered path
	 * matches the advertised `jwks_uri`.
	 */
	path?: string;
	/**
	 * `Cache-Control: public, max-age=<N>` lifetime in seconds for the JWKS
	 * response. Defaults to {@link DEFAULT_JWKS_CACHE_MAX_AGE}. Callers
	 * honoring `jwks.cacheMaxAge` resolve it via
	 * `resolveJwksCacheMaxAge`. Keep well below the key-overlap window so a
	 * freshly-rotated kid propagates to caching verifiers in time.
	 */
	cacheMaxAgeSeconds?: number;
	/**
	 * Where the `503 jwks_unavailable` answer is logged, at error level, as
	 * `jwks_unavailable` with the algorithm and the number of keys the
	 * keystore returned. Absent, it is not logged.
	 */
	logger?: EventLogger;
}

/**
 * Builds the JWKS publishing Router. `path` is registered as an absolute path,
 * so the endpoint is the mount point + `path`. Mount at the application root;
 * a prefix mount is valid only when the issuer carries the same prefix
 * (`jwks_uri = ${issuer}${path}`), or discovery advertises a `jwks_uri` that
 * does not resolve. `jwksModule` mounts at "/".
 *
 * Success carries `Cache-Control: public, max-age=<cacheMaxAgeSeconds>`. An
 * empty key set is never published: a symmetric (HS256) keystore answers
 * `404 jwks_not_published`, an asymmetric one with no exportable public key
 * `503 jwks_unavailable`, both `no-store` so a shared cache does not pin the
 * condition past the operator's fix.
 *
 * Direct callers bypass the config schema, so an invalid `path` or
 * `cacheMaxAgeSeconds` throws here, at boot.
 */
export const createRouter = (
	express: { Router: () => Router },
	keyStore: KeyStore,
	opts: JwksRouterOptions = {},
): Router => {
	const path = opts.path ?? DEFAULT_JWKS_PATH;
	if (!isValidJwksPath(path)) {
		throw new Error(
			`createJwksRouter: path must be an absolute path beginning with "/" ` +
				`(no "//", dot-segments, query/fragment, backslash, percent-encoding, or control chars), ` +
				`got ${JSON.stringify(path)}`,
		);
	}
	const cacheMaxAgeSeconds = opts.cacheMaxAgeSeconds ?? DEFAULT_JWKS_CACHE_MAX_AGE;
	if (!Number.isInteger(cacheMaxAgeSeconds) || cacheMaxAgeSeconds < 0) {
		throw new Error(
			`createJwksRouter: cacheMaxAgeSeconds must be a non-negative integer, got ${cacheMaxAgeSeconds}`,
		);
	}
	const router = express.Router();

	const cacheControl = `public, max-age=${cacheMaxAgeSeconds}`;

	// Export and hashing run once per key set, not per request: this is the
	// most-polled verifier endpoint. The cache is keyed on the set itself
	// ((kid, publicKey identity) pairs) because `KeyStore` has no rotation
	// event: the built-in store drops `previousKeys` on its own clock, and a
	// remote adapter may refresh at will. An adapter minting fresh key objects
	// per call simply recomputes per call.
	//
	// The strong `ETag` is the SHA-256 of the serialized set, so a verifier
	// sending `If-None-Match` gets `304` until the set changes. Error answers
	// (404/503) are never cached and carry no `ETag`: an empty set is a lie
	// that caches, and so is its tag.
	let cached: {
		keyRefs: readonly Pick<ManagedKey, "kid" | "publicKey">[];
		keys: readonly Record<string, unknown>[];
		etag: string;
	} | null = null;

	const byKid = (
		a: Pick<ManagedKey, "kid" | "publicKey">,
		b: Pick<ManagedKey, "kid" | "publicKey">,
	): number => (a.kid < b.kid ? -1 : a.kid > b.kid ? 1 : 0);

	// Order-insensitive: RFC 7517 gives key order no meaning, and the ETag
	// stays honest because the cached body is what is served. A duplicate kid
	// at worst fails the compare and recomputes, the safe direction.
	const sameKeySet = (
		current: readonly ManagedKey[],
		previous: readonly Pick<ManagedKey, "kid" | "publicKey">[],
	): boolean => {
		if (current.length !== previous.length) return false;
		const sortedCurrent = current
			.map((key) => ({ kid: key.kid, publicKey: key.publicKey }))
			.sort(byKid);
		const sortedPrevious = [...previous].sort(byKid);
		return sortedCurrent.every(
			(key, i) =>
				key.kid === sortedPrevious[i]?.kid && key.publicKey === sortedPrevious[i]?.publicKey,
		);
	};

	// The one `503` this route answers — no key to publish, or a keystore that
	// could not say — never cached, so the next request re-asks the keystore.
	const refuseUnavailable = (res: Response): Response => {
		res.setHeader("Cache-Control", "no-store");
		return res.status(503).json({
			error: "jwks_unavailable",
			error_description:
				"No public verification keys are currently available to publish. The signing " +
				"keystore returned no exportable public key material.",
		});
	};

	router.get(path, async (req: Request, res: Response) => {
		if (keyStore.algorithm === "HS256") {
			// An empty key set would look to a relying party like an issuer that
			// rotated every key away: it would cache it and fail every verification
			// with an unknown-kid error far from the cause. This deployment
			// publishes no JWKS, and says so. `no-store`: an operator can fix this
			// in a minute, and a shared cache would outlive the fix.
			res.setHeader("Cache-Control", "no-store");
			return res.status(404).json({
				error: "jwks_not_published",
				error_description:
					"This authorization server signs with HS256, a symmetric algorithm with no " +
					"public key to publish. Configure the key store with an asymmetric algorithm " +
					"(EdDSA, ES256 or RS256) to publish a verifiable JWKS.",
			});
		}
		let managedKeys: ManagedKey[];
		try {
			managedKeys = await keyStore.getVerificationKeys();
		} catch (err) {
			// A keystore that cannot answer — a remote key service timing out —
			// is the same outage as one with no key to publish: `503`, which a
			// relying party retries, rather than the terminal handler's `500`,
			// which reads as a broken server. Logged once, with the projection.
			opts.logger?.error(
				{ algorithm: keyStore.algorithm, err: loggableError(err) },
				"jwks_unavailable",
			);
			return refuseUnavailable(res);
		}
		if (cached === null || !sameKeySet(managedKeys, cached.keyRefs)) {
			const exported = await Promise.all(
				managedKeys.map(async (mk) => {
					const publicJwk = toPublicJwk((await exportJWK(mk.publicKey)) as Record<string, unknown>);
					if (publicJwk === null) return null;
					return { ...publicJwk, kid: mk.kid, use: "sig", alg: keyStore.algorithm };
				}),
			);
			const keys = exported.filter((k): k is NonNullable<typeof k> => k !== null);
			if (keys.length === 0) {
				// Nothing publishable from an asymmetric keystore (a KMS adapter
				// mid-rotation, or keys that all filtered out as non-public) is an
				// outage, not a publication: an empty set is a lie that caches. Not
				// cached, so the next request re-asks the keystore.
				opts.logger?.error(
					{ algorithm: keyStore.algorithm, keys: managedKeys.length },
					"jwks_unavailable",
				);
				return refuseUnavailable(res);
			}
			const body = JSON.stringify({ keys });
			cached = {
				keyRefs: managedKeys.map((mk) => ({ kid: mk.kid, publicKey: mk.publicKey })),
				keys,
				etag: `"${createHash("sha256").update(body).digest("base64url")}"`,
			};
		}
		// Set only after a successful export: set up front, a keystore outage
		// would reach Express's 5xx with `public, max-age` attached, and shared
		// caches would pin the transient error for the full lifetime.
		res.setHeader("Cache-Control", cacheControl);
		res.setHeader("ETag", cached.etag);
		// Optional chain: hand-built callers (and the route's own unit tests)
		// may stub a request without a headers bag.
		const ifNoneMatch = req.headers?.["if-none-match"];
		if (
			typeof ifNoneMatch === "string" &&
			ifNoneMatch
				.split(",")
				.map((tag) => tag.trim())
				.includes(cached.etag)
		) {
			return res.status(304).end();
		}
		return res.json({ keys: cached.keys });
	});

	return router;
};
