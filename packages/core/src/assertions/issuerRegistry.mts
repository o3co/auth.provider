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

import type { JSONWebKeySet, JWTPayload } from "jose";
import type { KeyLike } from "../keys/KeyStore.mjs";
import { isLoopbackHostname } from "../net/loopback.mjs";

/**
 * Where an issuer's signing keys come from (#525).
 *
 * - `key` — one public key, held in memory. The shape `createJwtAssertionVerifier`
 *   has always taken; rotation means re-registering.
 * - `jwks` — a static JSON Web Key Set, for an issuer that publishes several
 *   keys but no endpoint.
 * - `jwks_uri` — a remote JWKS endpoint, fetched on first use and cached. An
 *   unknown `kid` triggers a refetch (bounded by `cooldownMs`), which is how a
 *   rotation at the issuer is picked up without a restart. `https` is required
 *   unless the host is loopback: signing keys fetched over plaintext are keys
 *   an on-path attacker chose.
 */
export type AssertionIssuerKeySource =
	| { readonly type: "key"; readonly key: KeyLike }
	| { readonly type: "jwks"; readonly jwks: JSONWebKeySet }
	| {
			readonly type: "jwks_uri";
			readonly uri: string;
			/** How long a fetched set is served without refetching. Default 10 minutes. */
			readonly cacheMaxAgeMs?: number;
			/** Minimum interval between refetches triggered by an unknown `kid`. Default 30 s. */
			readonly cooldownMs?: number;
			/** Fetch timeout. Default 5 s. */
			readonly timeoutMs?: number;
	  };

/**
 * One issuer this deployment accepts RFC 7523 assertions from, and what it
 * accepts from them (#525).
 *
 * Every field beyond `issuer`, `keys` and `algorithms` is a ceiling: it can
 * only narrow what an assertion from this issuer may obtain, never widen the
 * request, the client registration or the policy. An entry is immutable
 * except for `expiresAt` — delete and re-add to change anything else, so the
 * audit trail of "what did we trust, and when" stays a list of adds and
 * removes.
 */
export interface AssertionIssuerEntry {
	/** The exact `iss` value. Matched by string equality, never by prefix. */
	readonly issuer: string;
	readonly keys: AssertionIssuerKeySource;
	/**
	 * Signature algorithms accepted from this issuer, e.g. `["EdDSA"]`. Required
	 * with no default: jose otherwise accepts anything the key can verify.
	 */
	readonly algorithms: readonly string[];
	/**
	 * `sub` values accepted from this issuer. Absent means any subject — the
	 * Store still decides whom a handle resolves to (#301).
	 */
	readonly allowedSubjects?: readonly string[];
	/**
	 * Scopes an assertion from this issuer may obtain. The verification result
	 * carries the intersection with the assertion's own `scope` claim (or this
	 * list when the assertion names none) as its scope ceiling.
	 */
	readonly allowedScopes?: readonly string[];
	/**
	 * Audiences a token minted from this issuer's assertions may name. A
	 * ceiling on the issued `aud` whatever chose it, and — with no
	 * authenticated client — the source the client registration would
	 * otherwise be (#520).
	 */
	readonly allowedAudiences?: readonly string[];
	/**
	 * Client ids permitted to present this issuer's assertions. Absent means
	 * any presenter, an unauthenticated one included (RFC 7523 §3 makes client
	 * authentication optional). A list admits those clients only; an
	 * unauthenticated presenter is refused.
	 */
	readonly allowedClients?: readonly string[];
	/** After this instant the entry is refused. The only mutable field. */
	readonly expiresAt?: Date;
	/**
	 * Which assertion profile this issuer mints (#526).
	 *
	 * - `"rfc7523"` (default): the plain RFC 7523 §2.1 assertion — `iss`,
	 *   `sub`, `aud` (any of the verifier's audiences), `exp`; a device
	 *   credential.
	 * - `"id-jag"`: the Identity Assertion JWT Authorization Grant an
	 *   enterprise IdP mints for a client. `typ` `oauth-id-jag+jwt`, `aud`
	 *   exactly this server's issuer identifier, `client_id` naming the
	 *   authenticated presenter, `jti` accepted once, and `scope` / `resource`
	 *   carried as claims. Needs `issuerIdentifier` and `replaySeenSet` on the
	 *   verifier.
	 */
	readonly profile?: "rfc7523" | "id-jag";
	/** Clock skew for `exp` / `nbf`, in seconds. Default 60. */
	readonly clockToleranceSeconds?: number;
	/** How the handle is read from the claims. Defaults to `sub`. */
	readonly readSubjectHandle?: (claims: JWTPayload) => string | null;
	/** How the scope ceiling is read from the claims. Defaults to `scope`, space-delimited. */
	readonly readScope?: (claims: JWTPayload) => readonly string[] | undefined;
}

/**
 * The lookup the registry verifier performs before any signature work: is
 * this `iss` one we trust, and on what terms?
 *
 * Throwing means the registry could not answer — a backing store being down —
 * and is surfaced as `503`, like every other outage on the verification path.
 * `null` is the answer for an issuer nobody registered.
 */
export interface AssertionIssuerRegistry {
	readonly kind: string;
	findIssuer(issuer: string): Promise<AssertionIssuerEntry | null>;
}

/**
 * The admin surface (#525): add, list, remove, and the one permitted edit.
 * Entries are otherwise immutable so that the history of what was trusted
 * is the history of adds and removes.
 */
export interface MutableAssertionIssuerRegistry extends AssertionIssuerRegistry {
	/** Refuses a duplicate `issuer` and a malformed entry. */
	add(entry: AssertionIssuerEntry): Promise<void>;
	list(): Promise<readonly AssertionIssuerEntry[]>;
	/** @returns whether an entry was removed. */
	remove(issuer: string): Promise<boolean>;
	/** @returns whether an entry was updated. */
	setExpiresAt(issuer: string, expiresAt: Date | undefined): Promise<boolean>;
}

/**
 * Validate an entry the way boot validates configuration: loudly, naming the
 * field. Shared by the memory registry and by anyone building an entry ahead
 * of registering it.
 */
export function checkAssertionIssuerEntry(entry: AssertionIssuerEntry): void {
	if (entry.issuer.length === 0) {
		throw new Error(
			"AssertionIssuerEntry: issuer is required — an assertion without a pinned " +
				"issuer is signed by anyone the key belongs to (RFC 7523 §3).",
		);
	}
	if (entry.algorithms.length === 0) {
		throw new Error(
			`AssertionIssuerEntry(${entry.issuer}): algorithms must name at least one ` +
				"algorithm — omitting it lets jose accept anything the key can verify.",
		);
	}
	if (entry.keys.type === "jwks_uri") {
		let url: URL;
		try {
			url = new URL(entry.keys.uri);
		} catch {
			throw new Error(
				`AssertionIssuerEntry(${entry.issuer}): keys.uri is not an absolute URL: ${entry.keys.uri}`,
			);
		}
		if (url.protocol !== "https:" && !isLoopbackHostname(url.hostname)) {
			throw new Error(
				`AssertionIssuerEntry(${entry.issuer}): keys.uri must be https — signing ` +
					"keys fetched over plaintext are keys an on-path attacker chose. " +
					"Loopback hosts are exempt for development.",
			);
		}
	}
}

/**
 * The in-memory registry: entries supplied at composition, mutable through
 * the admin surface, gone at restart. A deployment that registers issuers at
 * runtime and needs them to survive a restart implements
 * {@link AssertionIssuerRegistry} over its own store.
 */
export function createMemoryAssertionIssuerRegistry(
	entries: readonly AssertionIssuerEntry[] = [],
): MutableAssertionIssuerRegistry {
	const byIssuer = new Map<string, AssertionIssuerEntry>();
	const put = (entry: AssertionIssuerEntry): void => {
		checkAssertionIssuerEntry(entry);
		if (byIssuer.has(entry.issuer)) {
			throw new Error(
				`AssertionIssuerRegistry: issuer ${entry.issuer} is already registered — ` +
					"entries are immutable; remove it and add the new one.",
			);
		}
		byIssuer.set(entry.issuer, entry);
	};
	for (const entry of entries) put(entry);

	return {
		kind: "memory",
		async findIssuer(issuer) {
			return byIssuer.get(issuer) ?? null;
		},
		async add(entry) {
			put(entry);
		},
		async list() {
			return [...byIssuer.values()];
		},
		async remove(issuer) {
			return byIssuer.delete(issuer);
		},
		async setExpiresAt(issuer, expiresAt) {
			const current = byIssuer.get(issuer);
			if (current === undefined) return false;
			const { expiresAt: _dropped, ...rest } = current;
			byIssuer.set(issuer, expiresAt === undefined ? rest : { ...rest, expiresAt });
			return true;
		},
	};
}
