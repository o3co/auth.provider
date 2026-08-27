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
import type { Request, Response, Router } from "express";
import { exportJWK } from "jose";
import { DEFAULT_JWKS_CACHE_MAX_AGE } from "../jwks/cache.mjs";
import { DEFAULT_JWKS_PATH, isValidJwksPath } from "../jwks/path.mjs";
import type { KeyStore } from "../keys/KeyStore.mjs";

/**
 * JWK members that carry PRIVATE or SYMMETRIC key material and must never
 * appear in a published JWKS: RSA (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`),
 * EC/OKP (`d`), and symmetric (`k`). Per RFC 7517 §9.3 / RFC 7518.
 */
const PRIVATE_JWK_MEMBERS: readonly string[] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/**
 * Reduce an exported JWK to its public members, or drop it entirely.
 *
 * Defense-in-depth for the `KeyStore` public extension point: the built-in
 * stores only ever hold public verification material, but a third-party / KMS
 * adapter that mistakenly returns a private (or symmetric) key as `publicKey`
 * would otherwise have `exportJWK`'s private components spread straight into
 * the JWKS response. Symmetric (`kty: "oct"`) keys have no public
 * representation at all, so they are excluded (returns `null`); for asymmetric
 * keys the private members are stripped.
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
	 * {@link DEFAULT_JWKS_PATH}. Callers honoring the `oauth.jwt.jwksPath`
	 * override resolve it via `resolveJwksPath` and pass the result here so
	 * the registered path matches the advertised `jwks_uri`.
	 */
	path?: string;
	/**
	 * `Cache-Control: public, max-age=<N>` lifetime in seconds for the JWKS
	 * response. Defaults to {@link DEFAULT_JWKS_CACHE_MAX_AGE}. Callers
	 * honoring `oauth.jwt.jwksCacheMaxAge` resolve it via
	 * `resolveJwksCacheMaxAge`. Keep well below the key-overlap window so a
	 * freshly-rotated kid propagates to caching verifiers in time.
	 */
	cacheMaxAgeSeconds?: number;
}

/**
 * Build the JWKS publishing Router. The router registers `path` as an
 * **absolute** path internally, so the effective endpoint is the router's
 * mount point + `path`. Mount at the application root (`app.use(createRouter(
 * express, keyStore))`) for the common case. Prefix-mounting (e.g.
 * `app.use("/auth", createRouter(...))`) is valid only when the advertised
 * `jwks_uri` carries the same base path — typically because the issuer
 * identifier itself has that prefix (`jwks_uri = ${issuer}${path}`). If the
 * mount prefix and the issuer prefix disagree, discovery advertises a
 * `jwks_uri` that does not resolve. (The core `jwksModule` mounts at "/" and
 * relies on the issuer prefix to carry any base path.)
 *
 * A successful response carries `Cache-Control: public, max-age=N`, where N is
 * `cacheMaxAgeSeconds` (JWKS is public data and the most-polled verifier
 * endpoint).
 *
 * The route never publishes an empty key set (#282). A symmetric (HS256)
 * keystore answers `404 jwks_not_published`; an asymmetric keystore that
 * yields no exportable public key answers `503 jwks_unavailable`. Both carry
 * `Cache-Control: no-store` so the condition is not pinned in a shared cache
 * after the operator fixes it.
 *
 * Direct callers bypass the config schema, so `path` and `cacheMaxAgeSeconds`
 * are validated here and the factory throws on misconfiguration (a non-
 * absolute path or a negative / non-integer cache age) — failing fast at
 * boot rather than registering an unexpected route or emitting an invalid
 * `Cache-Control` header.
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

	router.get(path, async (_req: Request, res: Response) => {
		if (keyStore.algorithm === "HS256") {
			// #282: this used to answer `200 { keys: [] }`. An empty key set is
			// indistinguishable, to a relying party, from an issuer that has
			// rotated every key away — so the RP caches the empty answer and
			// then fails every verification with an unknown-kid error that
			// points nowhere near the actual cause. Refusing to serve says what
			// is true: this deployment publishes no JWKS at all.
			//
			// `no-store`, not `cacheControl`: this is a configuration state an
			// operator can fix in a minute, and a shared cache pinning it for
			// the full max-age would outlive the fix.
			res.setHeader("Cache-Control", "no-store");
			return res.status(404).json({
				error: "jwks_not_published",
				error_description:
					"This authorization server signs with HS256, a symmetric algorithm with no " +
					"public key to publish. Configure an asymmetric algorithm (EdDSA, ES256 or " +
					"RS256) via oauth.jwt.signingKey.local.algorithm to publish a verifiable JWKS.",
			});
		}
		const managedKeys = await keyStore.getVerificationKeys();
		const exported = await Promise.all(
			managedKeys.map(async (mk) => {
				const publicJwk = toPublicJwk((await exportJWK(mk.publicKey)) as Record<string, unknown>);
				if (publicJwk === null) return null;
				return { ...publicJwk, kid: mk.kid, use: "sig", alg: keyStore.algorithm };
			}),
		);
		const keys = exported.filter((k): k is NonNullable<typeof k> => k !== null);
		if (keys.length === 0) {
			// An asymmetric keystore that yields nothing publishable — a KMS
			// adapter mid-rotation, or one whose keys all filtered out as
			// non-public — is an outage, not a valid publication. Same reasoning
			// as the HS256 branch: an empty set is a lie that caches.
			res.setHeader("Cache-Control", "no-store");
			return res.status(503).json({
				error: "jwks_unavailable",
				error_description:
					"No public verification keys are currently available to publish. The signing " +
					"keystore returned no exportable public key material.",
			});
		}
		// Header set only after key export succeeded and produced at least one
		// key. If we set it up-front and `getVerificationKeys()`/`exportJWK()`
		// then threw (e.g. a remote KMS-backed keystore outage), Express would
		// emit a 5xx with the header still attached, and an explicit
		// `public, max-age` makes that transient error cacheable by shared
		// caches/CDNs for the full lifetime — turning a brief outage into a
		// stuck JWKS failure.
		res.setHeader("Cache-Control", cacheControl);
		return res.json({ keys });
	});

	return router;
};
