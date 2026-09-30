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

import type {
	FederatedIdentityLink,
	FederatedIdentityLookup,
	FederatedIdentityLookupResult,
	FederatedIdentityRegistration,
	LinkFederatedIdentityResult,
	User,
	UserRepository,
} from "@o3co/auth-provider-core";
import { assertSecureEndpoint, endpointForMessage } from "../endpointUrl.mjs";
import {
	bearerAuthorization,
	checkStoreResponseCap,
	checkStoreTimeout,
	DEFAULT_MAX_RESPONSE_BYTES,
	postToStore,
	type StoreRequestSettings,
} from "../storeTransport.mjs";

export { DEFAULT_MAX_RESPONSE_BYTES };

/** What this repository's messages lead with. */
const OWNER = "HttpUserRepository";

/** Whether a status is a `2xx`, the answers whose body is read. */
const isSuccess = (status: number): boolean => status >= 200 && status < 300;

/** The Store answered 409 to a link request: the identity is already someone else's. */
const CONFLICT = Symbol("conflict");

/**
 * Runtime guard for the Store's user response, so a malformed payload cannot
 * become a `User` with `undefined` required fields and leak `sub: undefined`
 * into authentication. Accepts any object with string `id` and `username`,
 * keeping the extras `User`'s index signature allows. Empty strings pass:
 * bcrypt compare and downstream gates prevent empty-credential authentication
 * in practice.
 */
function isUser(v: unknown): v is User {
	if (typeof v !== "object" || v === null) return false;
	const o = v as Record<string, unknown>;
	return typeof o.id === "string" && typeof o.username === "string";
}

/**
 * What the Store declares it can place: identities issued under one
 * registration (the federation's name, the issuer and the client, exactly as
 * a federation-grant connection is configured), given at least these claims
 * from the verified id_token. The boot probe is synchronous and cannot reach
 * the Store, so the operator relays the Store's own claim here; boot then
 * holds every connection to it. `requiredClaims = []` is a strategy on the
 * registration and the `sub` alone.
 */
export interface FederatedIdentityLookupCoverage {
	readonly provider: string;
	readonly issuer: string;
	readonly clientId: string;
	readonly requiredClaims: readonly string[];
}

const COVERAGE_FIELD = "federatedIdentityLookupCoverage";
const COVERAGE_KEYS: ReadonlySet<string> = new Set([
	"provider",
	"issuer",
	"clientId",
	"requiredClaims",
]);
/** A claim name: printable ASCII, no spaces (the shape the connection side accepts). */
const CLAIM_NAME = /^[\x21-\x7E]{1,256}$/;
const FORBIDDEN_CLAIM_NAMES: ReadonlySet<string> = new Set([
	"__proto__",
	"constructor",
	"prototype",
]);

/** A registration field: a non-empty string carrying no surrounding whitespace, compared exactly. */
const exactString = (value: unknown): value is string =>
	typeof value === "string" && value.length > 0 && value.trim() === value;

const coverageError = (at: string, problem: string): Error =>
	new Error(`HttpUserRepository: "${at}" ${problem}`);

/**
 * The declaration, checked field by field and frozen — the list, each entry
 * and each claim list — so that neither a later mutation of the caller's list
 * nor anything in-process holding the repository can widen what the boot
 * probe accepts. Diagnostics name the option, the entry and the field (a
 * field NAME an operator wrote wrongly is quoted) — never a value: a
 * registration's client id is configuration an operator may not want in a
 * log line.
 */
function validateCoverage(value: unknown): readonly FederatedIdentityLookupCoverage[] {
	if (value === undefined) return Object.freeze([]);
	if (!Array.isArray(value)) {
		throw coverageError(COVERAGE_FIELD, "must be a list of registrations");
	}
	const seen = new Set<string>();
	const entries = value.map((entry, index) => {
		const at = `${COVERAGE_FIELD}[${index}]`;
		if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
			throw coverageError(
				at,
				"must be an object with provider, issuer, clientId and requiredClaims",
			);
		}
		for (const key of Object.keys(entry)) {
			if (!COVERAGE_KEYS.has(key)) throw coverageError(at, `has a field it may not have: "${key}"`);
		}
		// Own properties only: a field that lives on the entry's prototype is
		// not one the operator wrote.
		const own = (field: string): unknown =>
			Object.hasOwn(entry, field) ? (entry as Record<string, unknown>)[field] : undefined;
		const provider = own("provider");
		const issuer = own("issuer");
		const clientId = own("clientId");
		const requiredClaims = own("requiredClaims");
		for (const [field, candidate] of [
			["provider", provider],
			["issuer", issuer],
			["clientId", clientId],
		] as const) {
			if (!exactString(candidate)) {
				throw coverageError(
					`${at}.${field}`,
					"must be a non-empty string without surrounding whitespace",
				);
			}
		}
		if (!Array.isArray(requiredClaims)) {
			throw coverageError(`${at}.requiredClaims`, "must be a list of claim names (empty for none)");
		}
		const names = new Set<string>();
		for (const name of requiredClaims) {
			if (typeof name !== "string" || !CLAIM_NAME.test(name) || FORBIDDEN_CLAIM_NAMES.has(name)) {
				throw coverageError(`${at}.requiredClaims`, "holds a name that is not a claim name");
			}
			if (names.has(name)) throw coverageError(`${at}.requiredClaims`, "lists a claim twice");
			names.add(name);
		}
		const key = JSON.stringify([provider, issuer, clientId]);
		if (seen.has(key))
			throw coverageError(at, "declares a registration an earlier entry already declares");
		seen.add(key);
		return Object.freeze({
			provider: provider as string,
			issuer: issuer as string,
			clientId: clientId as string,
			requiredClaims: Object.freeze([...names]),
		});
	});
	return Object.freeze(entries);
}

/** A lookup answer if it is one the port defines — a fresh object of the contract's fields, nothing else. */
function lookupAnswer(value: unknown): FederatedIdentityLookupResult | undefined {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
	const answer = value as {
		readonly kind?: unknown;
		readonly subject?: unknown;
		readonly reason?: unknown;
	};
	switch (answer.kind) {
		case "linked":
			return typeof answer.subject === "string" && answer.subject.length > 0
				? { kind: "linked", subject: answer.subject }
				: undefined;
		case "unlinked":
			return { kind: "unlinked" };
		case "indeterminate":
			return answer.reason === "registration_not_covered" ||
				answer.reason === "identity_not_resolvable"
				? { kind: "indeterminate", reason: answer.reason }
				: undefined;
		default:
			return undefined;
	}
}

/**
 * `UserRepository` backed by "the Store", the upstream user service defined
 * on core's `User` doc (`@o3co/auth-provider-core`, `src/repositories/types.mts`).
 * See README, The wire contract and Constructor validation.
 *
 * Every endpoint receives a plaintext credential or a verified identity, so
 * each is validated at **construction** (`src/endpointUrl.mts`), and no
 * request follows a redirect. With `bearerToken`, every request carries
 * `Authorization: Bearer <token>`, and a `401` or `403` with a `Bearer`
 * challenge throws a `StoreCredentialRefusedError`. A transport's own
 * error is never thrown, because it may quote the request: a failure throws a
 * `StoreTransportError` with a fixed message, at most an allowlisted transport
 * code, and no cause. Every message names an endpoint by origin and path
 * alone.
 */
export class HttpUserRepository implements UserRepository {
	/**
	 * `Bearer <token>`, or `undefined` for none. An ECMAScript private field
	 * rather than a TypeScript `private` one: `inspect()` and `JSON.stringify`
	 * see every other field of a repository handed to a logger, and not this.
	 */
	readonly #authorization: string | undefined;
	private authenticateUrl: string;
	private authenticateByTokenUrl: string;
	private timeout: number;
	private maxResponseBytes: number;
	private linkFederatedIdentityUrl?: string;
	private findSubjectByFederatedIdentityUrl?: string;
	private readonly coverage: readonly FederatedIdentityLookupCoverage[];
	/**
	 * See {@link UserRepository.linkFederatedIdentity}. Present only when
	 * `linkFederatedIdentityUrl` is configured, which is how the federation routes
	 * know to refuse `?link=1` up front instead of at the callback.
	 */
	readonly linkFederatedIdentity?: (
		userId: string,
		identity: FederatedIdentityLink,
	) => Promise<LinkFederatedIdentityResult>;
	/**
	 * See {@link UserRepository.supportsFederatedIdentityLookup}. Present
	 * together with the lookup, only when `findSubjectByFederatedIdentityUrl` is
	 * configured: absent, a deployment that requires the lookup is refused at
	 * boot by the method's name, which is the message that says what to set.
	 * Answers from the declaration alone — the Store is not asked at boot.
	 */
	readonly supportsFederatedIdentityLookup?: (
		registration: FederatedIdentityRegistration,
		identityClaims: readonly string[],
	) => boolean;
	/** See {@link UserRepository.findSubjectByFederatedIdentity}. Present with the probe. */
	readonly findSubjectByFederatedIdentity?: (
		identity: FederatedIdentityLookup,
	) => Promise<FederatedIdentityLookupResult>;

	constructor({
		authenticateUrl,
		authenticateByTokenUrl,
		linkFederatedIdentityUrl,
		findSubjectByFederatedIdentityUrl,
		federatedIdentityLookupCoverage,
		bearerToken,
		timeout,
		maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
	}: {
		authenticateUrl: string;
		authenticateByTokenUrl: string;
		/** Optional; the Store's link endpoint. Same https rule as the other two. */
		linkFederatedIdentityUrl?: string;
		/** Optional; the Store's identity lookup. Same https rule; carries a verified identity. */
		findSubjectByFederatedIdentityUrl?: string;
		/** Which registrations the Store's lookup covers. Needs the URL; `[]` covers none. */
		federatedIdentityLookupCoverage?: readonly FederatedIdentityLookupCoverage[];
		/**
		 * Optional; sent to the Store on every request as `Authorization: Bearer
		 * <token>`. A bare RFC 6750 token (no scheme) of at least
		 * `MIN_SECRET_ENTROPY_BYTES` of key material — `openssl rand -hex 32`.
		 */
		bearerToken?: string;
		timeout: number;
		maxResponseBytes?: number;
	}) {
		this.authenticateUrl = assertSecureEndpoint(authenticateUrl, "authenticateUrl");
		this.authenticateByTokenUrl = assertSecureEndpoint(
			authenticateByTokenUrl,
			"authenticateByTokenUrl",
		);
		this.#authorization = bearerAuthorization(bearerToken, OWNER);
		if (linkFederatedIdentityUrl !== undefined) {
			this.linkFederatedIdentityUrl = assertSecureEndpoint(
				linkFederatedIdentityUrl,
				"linkFederatedIdentityUrl",
			);
			this.linkFederatedIdentity = (userId, identity) => this.linkViaHttp(userId, identity);
		}
		this.coverage = validateCoverage(federatedIdentityLookupCoverage);
		if (findSubjectByFederatedIdentityUrl !== undefined) {
			this.findSubjectByFederatedIdentityUrl = assertSecureEndpoint(
				findSubjectByFederatedIdentityUrl,
				"findSubjectByFederatedIdentityUrl",
			);
			this.supportsFederatedIdentityLookup = (registration, identityClaims) =>
				// A list, as the port types it: `includes` on a string would match
				// a substring, and a caller that is not the boot probe may hand
				// over anything.
				Array.isArray(identityClaims) &&
				(this.declared(registration)?.requiredClaims.every((name) =>
					identityClaims.includes(name),
				) ??
					false);
			this.findSubjectByFederatedIdentity = (identity) => this.lookupViaHttp(identity);
		} else if (this.coverage.length > 0) {
			throw new Error(
				`HttpUserRepository: "${COVERAGE_FIELD}" declares what the Store's lookup covers, and no ` +
					'"findSubjectByFederatedIdentityUrl" names that lookup — set the URL, or remove the declaration',
			);
		}

		this.timeout = checkStoreTimeout(timeout, OWNER);
		this.maxResponseBytes = checkStoreResponseCap(maxResponseBytes, OWNER);
	}

	/**
	 * What every request is sent with: the credential, when configured, the
	 * deadline and the cap. A `401` or `403` with a `Bearer` challenge to a
	 * request that carried the credential throws `StoreCredentialRefusedError`
	 * before any other reading of the status (`postToStore`): otherwise a
	 * token the Store does not accept is every login "no such user" and every
	 * link "refused", with nothing logged.
	 */
	private settings(): StoreRequestSettings {
		return {
			authorization: this.#authorization,
			timeout: this.timeout,
			maxResponseBytes: this.maxResponseBytes,
		};
	}

	async authenticate(username: string, password: string): Promise<User | null> {
		// Without `acceptConflict` the sentinel is never produced — a 409 throws.
		return this.post(this.authenticateUrl, { email: username, password }) as Promise<User | null>;
	}

	async authenticateByToken(token: string): Promise<User | null> {
		return this.post(this.authenticateByTokenUrl, { token }) as Promise<User | null>;
	}

	/**
	 * POST `{ userId, provider, sub, token, claims }` to the Store's link
	 * endpoint. A `2xx` `User` is the linked account; `401` / `403` is the Store's
	 * refusal (policy — an unverified or relay address, one identity per
	 * provider, …); `409` says the identity is already someone else's.
	 */
	private async linkViaHttp(
		userId: string,
		identity: FederatedIdentityLink,
	): Promise<LinkFederatedIdentityResult> {
		const url = this.linkFederatedIdentityUrl as string;
		const answer = await this.post(url, { userId, ...identity }, { acceptConflict: true });
		if (answer === CONFLICT) return { ok: false, reason: "conflict" };
		if (answer === null) return { ok: false, reason: "refused" };
		return { ok: true, user: answer };
	}

	/** The declaration for a registration, if the operator made one. Exact on all three. */
	private declared(
		registration: FederatedIdentityRegistration,
	): FederatedIdentityLookupCoverage | undefined {
		return this.coverage.find(
			(entry) =>
				entry.provider === registration.provider &&
				entry.issuer === registration.issuer &&
				entry.clientId === registration.clientId,
		);
	}

	/**
	 * POST `{ provider, issuer, clientId, sub, claims }` to the Store's lookup
	 * and read one of the port's three answers. Answered locally, with
	 * no request, where the declaration already decides: a registration nobody
	 * declared is `registration_not_covered`, and a declared one arriving
	 * without a claim its strategy needs is `identity_not_resolvable`. Every
	 * claim the connection supplied is sent, not only the required ones: what
	 * the Store matches on is the Store's business.
	 */
	private async lookupViaHttp(
		identity: FederatedIdentityLookup,
	): Promise<FederatedIdentityLookupResult> {
		const entry = this.declared(identity);
		if (entry === undefined) return { kind: "indeterminate", reason: "registration_not_covered" };
		for (const name of entry.requiredClaims) {
			const value = Object.hasOwn(identity.claims, name) ? identity.claims[name] : undefined;
			if (typeof value !== "string" || value.length === 0) {
				return { kind: "indeterminate", reason: "identity_not_resolvable" };
			}
		}
		return this.postLookup(this.findSubjectByFederatedIdentityUrl as string, {
			provider: identity.provider,
			issuer: identity.issuer,
			clientId: identity.clientId,
			sub: identity.sub,
			claims: { ...identity.claims },
		});
	}

	/**
	 * The lookup's transport: the same deadline, cap and abort as {@link post},
	 * and like it never follows a redirect (the body carries a verified identity,
	 * and a `Location` is not a configured endpoint). None of {@link post}'s
	 * readings: only a `2xx` carrying one of the three answers is an answer.
	 * Everything else throws as an outage, except a `401` or `403` with a
	 * `Bearer` challenge to a request that carried the token, which throws as the
	 * refused credential it is. What is thrown names the endpoint by origin and
	 * path, plus the status for an answer or at most the code for a transport
	 * failure, and never the body, the identity, a status text or a cause.
	 */
	private async postLookup(url: string, body: unknown): Promise<FederatedIdentityLookupResult> {
		// What every message names: origin and path, never the query.
		const endpoint = endpointForMessage(url);
		const { response, text } = await postToStore(
			url,
			body,
			this.settings(),
			{
				owner: OWNER,
				unreachable: `HttpUserRepository: identity lookup at ${endpoint} could not be reached`,
				closed: `HttpUserRepository: identity lookup at ${endpoint}: the connection closed before a complete response arrived`,
				malformed: `HttpUserRepository: identity lookup at ${endpoint} answered with a malformed HTTP response`,
				unreadable: `HttpUserRepository: identity lookup at ${endpoint} could not be read`,
			},
			isSuccess,
		);
		if (text === undefined) {
			throw new Error(
				`HttpUserRepository: identity lookup at ${endpoint} answered HTTP ${response.status}`,
			);
		}
		let parsed: unknown;
		try {
			parsed = JSON.parse(text);
		} catch {
			throw new Error(`HttpUserRepository: upstream ${endpoint} returned a non-JSON body`);
		}
		const answer = lookupAnswer(parsed);
		if (answer === undefined) {
			throw new Error(
				`HttpUserRepository: identity lookup at ${endpoint} answered a body that is not one of the ` +
					"port's answers (linked / unlinked / indeterminate)",
			);
		}
		return answer;
	}

	private async post(
		url: string,
		body: unknown,
		options: { acceptConflict?: boolean } = {},
	): Promise<User | null | typeof CONFLICT> {
		// What every message names: origin and path, never the query.
		const endpoint = endpointForMessage(url);
		// Never follows a redirect (`postToStore`): a 307 or 308 would re-send
		// the body — a password, a token, a link request — to a `Location` the
		// https rule never checked, and a 3xx is not a 2xx, 401, 403 or 409, so
		// it throws below as an unexpected status.
		const { response, text } = await postToStore(
			url,
			body,
			this.settings(),
			{
				owner: OWNER,
				unreachable: `HttpUserRepository: request to ${endpoint} could not be reached`,
				closed: `HttpUserRepository: the connection to ${endpoint} closed before a complete response arrived`,
				malformed: `HttpUserRepository: the Store at ${endpoint} answered with a malformed HTTP response`,
				unreadable: `HttpUserRepository: response from ${endpoint} could not be read`,
			},
			isSuccess,
		);
		if (text !== undefined) {
			let parsed: unknown;
			try {
				parsed = JSON.parse(text);
			} catch {
				// Same class of failure as the shape check below: the Store is
				// broken, not the credential.
				throw new Error(`HttpUserRepository: upstream ${endpoint} returned a non-JSON body`);
			}
			if (!isUser(parsed)) {
				// A 2xx with an unexpected shape is an upstream failure, not "no
				// such user": thrown rather than answered null.
				throw new Error(`HttpUserRepository: upstream ${endpoint} returned an invalid User shape`);
			}
			return parsed;
		}
		if (options.acceptConflict && response.status === 409) {
			return CONFLICT;
		}
		if (response.status === 401 || response.status === 403) {
			return null;
		}
		throw new Error(`Unexpected HTTP status ${response.status} from ${endpoint}`);
	}
}
