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

import type { JSONWebKeySet } from "jose";
import type { KeyLike } from "../keys/KeyStore.mjs";
import { isLoopbackHostname } from "../net/loopback.mjs";
import {
	describeMalformedIdentifier,
	isWellFormedIdentifier,
	MAX_IDENTIFIER_LENGTH,
} from "../security/identifier.mjs";
import {
	describeInvalidAssertionClockTolerance,
	isValidAssertionClockTolerance,
} from "./lifetime.mjs";

/**
 * Where an issuer's signing keys come from.
 *
 * - `key`: one public key held in memory; rotation means re-registering.
 * - `jwks`: a static JSON Web Key Set, for an issuer that publishes several
 *   keys but no endpoint.
 * - `jwks_uri`: a remote JWKS endpoint, fetched on first use and cached. An
 *   unknown `kid` triggers a refetch (bounded by `cooldownMs`), so a rotation
 *   at the issuer is picked up without a restart. `https` is required unless
 *   the host is loopback: keys fetched over plaintext are keys an on-path
 *   attacker chose.
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
 * One issuer this deployment accepts RFC 7523 assertions from, and on what
 * terms, as a caller writes it (the composition's entry list, and `add`). A
 * registry answers with {@link AssertionIssuerEntry}, where no field is
 * optional. Optional fields also admit an explicit `undefined`, so `list()`
 * feeds `add()` under `exactOptionalPropertyTypes`.
 *
 * Every field beyond `issuer`, `keys` and `algorithms` is a ceiling: it only
 * narrows what an assertion may obtain, never widens the request, the client
 * registration or the policy. Absent means no ceiling.
 *
 * An entry is data: it survives a JSON round trip (`expiresAt` revived as a
 * `Date`), except `keys.type: "key"`, a live key object; a store-backed
 * registry holds `jwks` (a one-key set is fine) or `jwks_uri`. Claim readers
 * are code and belong to the verifier
 * (`RegistryAssertionVerifierOptions.readersFor`). Only `expiresAt` is
 * mutable (delete and re-add to change anything else), so the trust history
 * stays a list of adds and removes.
 */
export interface AssertionIssuerEntryInput {
	/** The exact `iss` value. Matched by string equality, never by prefix. */
	readonly issuer: string;
	readonly keys: AssertionIssuerKeySource;
	/**
	 * Signature algorithms accepted from this issuer, e.g. `["EdDSA"]`. Required
	 * with no default: jose otherwise accepts anything the key can verify.
	 */
	readonly algorithms: readonly string[];
	/**
	 * `sub` values accepted from this issuer. Absent means any subject; the
	 * Store still decides whom a handle resolves to.
	 */
	readonly allowedSubjects?: readonly string[] | undefined;
	/**
	 * Scopes an assertion from this issuer may obtain. The verification result
	 * carries the intersection with the assertion's own `scope` claim (or this
	 * list when the assertion names none) as its scope ceiling.
	 */
	readonly allowedScopes?: readonly string[] | undefined;
	/**
	 * Audiences a token minted from this issuer's assertions may name. A
	 * ceiling on the issued `aud` whatever chose it, and, with no
	 * authenticated client, the source the client registration would
	 * otherwise be.
	 */
	readonly allowedAudiences?: readonly string[] | undefined;
	/**
	 * Client ids permitted to present this issuer's assertions. Absent means
	 * any presenter, an unauthenticated one included (RFC 7523 §3 makes client
	 * authentication optional). A list admits those clients only; an
	 * unauthenticated presenter is refused.
	 */
	readonly allowedClients?: readonly string[] | undefined;
	/**
	 * After this instant the entry is refused. The only mutable field. A
	 * registry over a store hands it back as a `Date`.
	 */
	readonly expiresAt?: Date | undefined;
	/**
	 * Which assertion profile this issuer mints.
	 *
	 * - `"rfc7523"` (default): the plain RFC 7523 §2.1 assertion (`iss`, `sub`,
	 *   `aud` any of the verifier's audiences, `exp`); a device credential.
	 * - `"id-jag"`: the Identity Assertion JWT Authorization Grant an enterprise
	 *   IdP mints for a client: `typ` `oauth-id-jag+jwt`, `aud` exactly this
	 *   server's issuer identifier, `client_id` naming the authenticated
	 *   presenter, `jti` accepted once, `scope` / `resource` as claims. Needs
	 *   `issuerIdentifier` and `replaySeenSet` on the verifier.
	 */
	readonly profile?: "rfc7523" | "id-jag" | undefined;
	/**
	 * Clock skew for `exp` / `nbf`, in seconds. Default 60. A finite number
	 * from 0 to `MAX_ASSERTION_CLOCK_TOLERANCE_SECONDS` (300): it is added to
	 * the lifetime ceiling and to every time check, so `NaN`, `Infinity` or a
	 * string would switch them off. Checked by {@link checkAssertionIssuerEntry}
	 * and again when the verifier reads a stored entry. An assertion admitted
	 * past its `exp` inside this tolerance verifies but leaves no lifetime for
	 * a token to inherit, so the jwt-bearer grant refuses it.
	 */
	readonly clockToleranceSeconds?: number | undefined;
}

/**
 * An issuer entry as a registry holds and answers with it: every field of
 * {@link AssertionIssuerEntryInput} as a REQUIRED key, `undefined` where the
 * entry names no ceiling.
 *
 * A registry that loses a ceiling fails open: `allowedClients` gone admits any
 * presenter (an unauthenticated one too, unless the entry is ID-JAG, whose
 * presenter must authenticate); `expiresAt` gone trusts the issuer forever;
 * `profile: "id-jag"` gone falls back to plain RFC 7523 and drops the `jti`
 * replay, `typ` and exact-`aud` checks. (`clockToleranceSeconds` gone restores
 * the default, looser or stricter than configured.) So a store-backed registry,
 * this port's documented way to survive a restart, reads each row back as an
 * object literal of THIS type naming every field: a forgotten key then fails
 * to compile instead of dropping the ceiling.
 *
 * The guarantee is the literal's alone. It is lost by mapping a row through
 * {@link toAssertionIssuerEntry} (which takes the optional input type), in
 * plain JavaScript, behind a cast (`as AssertionIssuerEntry`,
 * `JSON.parse(row) as …`), or through a store row type with optional keys
 * (declare every key required there too). It does not reach inside `keys`:
 * losing a `jwks_uri` source's `cacheMaxAgeMs` restores the ten-minute
 * default, a bounded widening of how long a key withdrawn at the issuer is
 * still accepted.
 */
export interface AssertionIssuerEntry {
	readonly issuer: string;
	readonly keys: AssertionIssuerKeySource;
	readonly algorithms: readonly string[];
	readonly allowedSubjects: readonly string[] | undefined;
	readonly allowedScopes: readonly string[] | undefined;
	readonly allowedAudiences: readonly string[] | undefined;
	readonly allowedClients: readonly string[] | undefined;
	readonly expiresAt: Date | undefined;
	readonly profile: "rfc7523" | "id-jag" | undefined;
	readonly clockToleranceSeconds: number | undefined;
}

/**
 * Fields that are code and belong to the verifier (`readersFor`), not to an
 * entry. An entry carrying one is refused rather than ignored: ignoring a
 * handle reader would hand the Store a bare `sub` that two issuers can share.
 */
const READER_FIELDS = ["readSubjectHandle", "readScope"] as const;

/**
 * The lookup the registry verifier performs before any signature work: is
 * this `iss` trusted, and on what terms?
 *
 * Throw only when the registry cannot answer (a backing store down); that
 * surfaces as `503`, like every outage on the verification path. Answer
 * `null` for an unregistered issuer and never throw for one, or a client's
 * made-up `iss` becomes the server's outage.
 *
 * `issuer` is untrusted input, read before any signature is checked. The
 * verifier passes only a well-formed identifier (1 to 256 characters, no
 * control character: core's identifier rule), but any other character may be
 * in it. A store-backed registry binds it as a query parameter and never
 * interpolates it into a query, a path or a URL.
 */
export interface AssertionIssuerRegistry {
	readonly kind: string;
	findIssuer(issuer: string): Promise<AssertionIssuerEntry | null>;
}

/**
 * The admin surface: add, list, remove, and the one permitted edit.
 * Entries are otherwise immutable so that the history of what was trusted
 * is the history of adds and removes.
 *
 * An edit reaches the registry it is made on. For the memory registry that is
 * one process: see {@link createMemoryAssertionIssuerRegistry}.
 */
export interface MutableAssertionIssuerRegistry extends AssertionIssuerRegistry {
	/** Refuses a duplicate `issuer` and a malformed entry. */
	add(entry: AssertionIssuerEntryInput): Promise<void>;
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
 *
 * Run it on what the caller wrote, BEFORE {@link toAssertionIssuerEntry},
 * which copies only the entry's own fields and would silently strip a reader
 * function that must be refused (see `READER_FIELDS`).
 */
export function checkAssertionIssuerEntry(entry: AssertionIssuerEntryInput): void {
	for (const field of READER_FIELDS) {
		if ((entry as unknown as Record<string, unknown>)[field] !== undefined) {
			throw new Error(
				`AssertionIssuerEntry(${entry.issuer}): ${field} is not an entry field — an entry is ` +
					"data a store can hold, and a reader is code. Pass it through the verifier's " +
					"readersFor(entry) instead.",
			);
		}
	}
	if (entry.issuer.length === 0) {
		throw new Error(
			"AssertionIssuerEntry: issuer is required — an assertion without a pinned " +
				"issuer is signed by anyone the key belongs to (RFC 7523 §3).",
		);
	}
	// An issuer no assertion could name — the verifier refuses such an `iss`
	// before the lookup — would be a registration that never matches. The
	// value is not repeated: it may carry control characters.
	if (!isWellFormedIdentifier(entry.issuer)) {
		throw new Error(
			`AssertionIssuerEntry: issuer is not an identifier an assertion can name ` +
				`(${describeMalformedIdentifier(entry.issuer)}); it must be a string of 1 to ` +
				`${MAX_IDENTIFIER_LENGTH} characters with no control character.`,
		);
	}
	if (entry.algorithms.length === 0) {
		throw new Error(
			`AssertionIssuerEntry(${entry.issuer}): algorithms must name at least one ` +
				"algorithm — omitting it lets jose accept anything the key can verify.",
		);
	}
	if (
		entry.clockToleranceSeconds !== undefined &&
		!isValidAssertionClockTolerance(entry.clockToleranceSeconds)
	) {
		throw new Error(
			`AssertionIssuerEntry(${entry.issuer}): ${describeInvalidAssertionClockTolerance(entry.clockToleranceSeconds)}.`,
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
 * The stored form of an input a caller wrote (what `add` receives, what the
 * composition lists): every field named, `undefined` where a ceiling was left
 * out. Copies the entry's own fields only, so validate the input first
 * ({@link checkAssertionIssuerEntry}). Not for reading a store's rows back:
 * see {@link AssertionIssuerEntry}.
 */
export function toAssertionIssuerEntry(input: AssertionIssuerEntryInput): AssertionIssuerEntry {
	return {
		issuer: input.issuer,
		keys: input.keys,
		algorithms: input.algorithms,
		allowedSubjects: input.allowedSubjects,
		allowedScopes: input.allowedScopes,
		allowedAudiences: input.allowedAudiences,
		allowedClients: input.allowedClients,
		expiresAt: input.expiresAt,
		profile: input.profile,
		clockToleranceSeconds: input.clockToleranceSeconds,
	};
}

/**
 * The in-memory registry: entries supplied at composition, mutable through
 * the admin surface, gone at restart. A deployment that registers issuers at
 * runtime and needs them to survive a restart implements
 * {@link AssertionIssuerRegistry} over its own store.
 *
 * Replicas: a static registry is replica-safe, but `add`, `remove` and
 * `setExpiresAt` change this process only. An issuer revoked on one replica
 * stays trusted on the others, and a restart restores it from the
 * composition's entries. `deployment.mode = "multi"` cannot refuse this (the
 * registry sits inside the `assertionVerifier`, not on a module manifest the
 * boot guard reads), so a multi-replica deployment changes the entry list by
 * redeploying, or keeps it in a shared store.
 */
export function createMemoryAssertionIssuerRegistry(
	entries: readonly AssertionIssuerEntryInput[] = [],
): MutableAssertionIssuerRegistry {
	const byIssuer = new Map<string, AssertionIssuerEntry>();
	const put = (entry: AssertionIssuerEntryInput): void => {
		checkAssertionIssuerEntry(entry);
		if (byIssuer.has(entry.issuer)) {
			throw new Error(
				`AssertionIssuerRegistry: issuer ${entry.issuer} is already registered — ` +
					"entries are immutable; remove it and add the new one.",
			);
		}
		byIssuer.set(entry.issuer, toAssertionIssuerEntry(entry));
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
			// The key stays; only its value changes — `undefined` clears it.
			byIssuer.set(issuer, { ...current, expiresAt });
			return true;
		},
	};
}
