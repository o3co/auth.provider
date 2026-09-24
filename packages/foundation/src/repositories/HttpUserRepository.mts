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
	describeWeakSecret,
	type FederatedIdentityLink,
	type FederatedIdentityLookup,
	type FederatedIdentityLookupResult,
	type FederatedIdentityRegistration,
	type LinkFederatedIdentityResult,
	MIN_SECRET_ENTROPY_BYTES,
	measureSecretEntropyBytes,
	type User,
	type UserRepository,
} from "@o3co/auth-provider-core";
import { assertSecureEndpoint } from "../endpointUrl.mjs";
import { readFailure, requestFailure, StoreCredentialRefusedError } from "./storeErrors.mjs";
import { hasBearerChallenge } from "./wwwAuthenticate.mjs";

/** The Store answered 409 to a link request: the identity is already someone else's (#482). */
const CONFLICT = Symbol("conflict");

/**
 * Default ceiling on an upstream response body, in bytes.
 *
 * A `User` record is a few hundred bytes; 1 MiB is generous for one carrying
 * custom claims and small enough that a hostile or broken Store cannot walk the
 * process out of memory one login at a time (#285).
 */
export const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;

/**
 * Largest delay Node's timer subsystem represents. Anything above it is
 * silently clamped to 1ms — so an operator writing a very large number meaning
 * "be patient" would otherwise get the most impatient timeout possible.
 */
const MAX_TIMEOUT_MS = 2_147_483_647;

/**
 * Runtime guard for the upstream user-service response. The previous
 * `(await res.json()) as User` was a compile-time cast only — a malformed
 * upstream payload (`{ status: "ok" }`, schema migration, tampered
 * response) silently produced a `User` with `undefined` required fields,
 * leaking `sub: undefined` into the authentication flow.
 *
 * The guard accepts any object with string `id` and `username`,
 * preserving the index-signature `[key: string]: unknown` extras that
 * `User` allows. Empty strings pass — bcrypt compare and downstream
 * gates prevent empty-credential authentication in practice; tightening
 * to `.min(1)` is a Phase F follow-up if needed.
 *
 * Per TS-2 (Wave 5g).
 */
function isUser(v: unknown): v is User {
	if (typeof v !== "object" || v === null) return false;
	const o = v as Record<string, unknown>;
	return typeof o.id === "string" && typeof o.username === "string";
}

/**
 * What the Store declares it can place (#613): identities issued under one
 * registration — the federation's name, the issuer and the client, exactly as
 * a federation-grant connection is configured — given at least these claims
 * from the verified id_token. The synchronous probe D7 check 5 asks at boot
 * cannot reach the Store, so the operator relays the Store's own claim here;
 * boot then holds every connection to it. `requiredClaims = []` is a strategy
 * on the registration and the `sub` alone.
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
 * RFC 6750 §2.1 `b64token` — the characters a bearer credential may carry.
 * Nothing in it is whitespace or a control character, so a token that
 * matches cannot break the header it rides in.
 */
const B64TOKEN = /^[A-Za-z0-9\-._~+/]+=*$/;

const BEARER_TOKEN_FIELD = "bearerToken";

/**
 * The credential presented to the Store, checked (#285's rule: at
 * construction, so a deployment that would send an unusable one fails at
 * boot) and turned into the `Authorization` value; `undefined` when none is
 * configured, which sends no `Authorization` header at all.
 *
 * The shape is refused here and not left to `fetch`: a header value `fetch`
 * refuses is one it QUOTES in the `TypeError` it throws, on the request path,
 * where the session routes log what is thrown. The strength is core's
 * shared-secret floor (`MIN_SECRET_ENTROPY_BYTES`, measured on the decoded
 * length as `SESSION_SECRET` is): whoever holds this token speaks to the Store
 * as auth.provider — resolves an identity to its user, links one to any user.
 * No message quotes the value.
 */
function bearerAuthorization(value: unknown): string | undefined {
	if (value === undefined) return undefined;
	const refuse = (problem: string): Error =>
		new Error(`HttpUserRepository: "${BEARER_TOKEN_FIELD}" ${problem}`);
	if (typeof value !== "string") throw refuse("must be a string");
	if (value === "") {
		throw refuse(
			'must not be empty — HOCON substitutes an exported-but-empty variable as ""; ' +
				"leave it unset to send no Authorization header",
		);
	}
	if (!B64TOKEN.test(value)) {
		throw refuse(
			"must be a bare RFC 6750 token: letters, digits and - . _ ~ + /, then optional = padding — " +
				'no whitespace, no line break, and no "Bearer " prefix (the scheme is added)',
		);
	}
	const actualBytes = measureSecretEntropyBytes(value);
	if (actualBytes < MIN_SECRET_ENTROPY_BYTES) {
		throw new Error(
			`HttpUserRepository: ${describeWeakSecret(actualBytes, {
				configKey: "repositories.user.http.bearerToken",
				envVar: "CLIENT_USER_BEARER_TOKEN",
			})}`,
		);
	}
	return `Bearer ${value}`;
}

/** Whether `value` is a positive integer that fits `bound`. */
function isPositiveIntegerWithin(value: unknown, bound: number): value is number {
	return typeof value === "number" && Number.isInteger(value) && value > 0 && value <= bound;
}

/**
 * Releases a response body we are not going to read.
 *
 * Without this an error or 401 leaves the body unconsumed, and undici holds the
 * socket until the response is garbage collected rather than returning it to
 * the keep-alive pool — a slow leak on the failure path, which is exactly the
 * path a struggling deployment spends its time on.
 *
 * Deliberately not awaited: cancelling is a signal to the transport, and how
 * long the peer takes to act on it is the peer's business. Awaiting would hand
 * a hostile Store a second way to stall the caller — the one the request
 * deadline exists to close — and some interceptors never settle it at all.
 */
function discardBody(res: Response): void {
	res.body?.cancel().catch(() => {
		// Already consumed, already errored, or aborted — nothing to release.
	});
}

/**
 * Reads at most `limit` bytes of `res` and returns them as text, throwing once
 * the limit is passed.
 *
 * `Content-Length` is checked first so an honest oversized response is refused
 * before a byte of it is read, but the streaming count is the load-bearing
 * half: a hostile Store simply omits the header (or lies), and chunked transfer
 * encoding has none to omit.
 *
 * Everything it throws is the adapter's own: the cap, the deadline's
 * rejection, or — for a stream that broke mid-read — what `unreadable` makes
 * of the transport's error, which is never passed on as it is.
 */
async function readBodyCapped(
	res: Response,
	limit: number,
	url: string,
	deadline: Promise<never>,
	unreadable: (err: unknown) => Error,
): Promise<string> {
	const declared = Number(res.headers.get("content-length"));
	if (Number.isFinite(declared) && declared > limit) {
		discardBody(res);
		throw new Error(
			`HttpUserRepository: upstream ${url} response exceeds the ${limit}-byte cap ` +
				`(Content-Length: ${declared})`,
		);
	}

	if (res.body === null) return "";

	const reader = res.body.getReader();
	const decoder = new TextDecoder();
	let text = "";
	let read = 0;
	try {
		for (;;) {
			// Raced against the deadline rather than relying on `signal` alone:
			// aborting a request does not reliably interrupt a `read()` already
			// in flight, which is exactly the slow-loris shape — headers arrive
			// promptly, then the body dribbles or stops. One absolute deadline
			// for the whole exchange, not a fresh one per chunk.
			const { done, value } = await Promise.race([
				reader.read().catch((err: unknown) => {
					throw unreadable(err);
				}),
				deadline,
			]);
			if (done) break;
			read += value.byteLength;
			if (read > limit) {
				throw new Error(
					`HttpUserRepository: upstream ${url} response exceeds the ${limit}-byte cap`,
				);
			}
			text += decoder.decode(value, { stream: true });
		}
	} finally {
		// Tears down the connection when we bail out early; a no-op once the
		// stream has completed on its own. Not awaited, for the reason given on
		// `discardBody`.
		reader.cancel().catch(() => {});
	}
	return text + decoder.decode();
}

/**
 * Whether `err` is the abort our own deadline raised on the `fetch` itself —
 * the case where the response headers never arrive.
 *
 * A deliberately shallow check. An aborted `fetch` rejects with the
 * `AbortError` directly; the wrapping that `fetch` does apply is for network
 * failures, which are not aborts. If some runtime did wrap one, the request
 * still fails — as a `StoreTransportError` ("could not be reached") instead of
 * a `TimeoutError`, a misnamed failure rather than a missed one, and not worth
 * an untestable `cause` walk.
 * A stalled *body* is not covered here at all: that is the deadline race in
 * `readBodyCapped`, which does not depend on abort semantics.
 */
function isAbortError(err: unknown): boolean {
	// Optional chaining rather than a `typeof` guard: it covers `null`,
	// `undefined` and a thrown primitive in the same expression, with no
	// branch that only a contrived throw could reach.
	const name = (err as { name?: unknown } | null | undefined)?.name;
	return name === "AbortError" || name === "TimeoutError";
}

/**
 * `UserRepository` backed by "the Store" — the upstream user service defined
 * on core's `User` doc (`@o3co/auth-provider-core`, `src/repositories/types.mts`).
 *
 * Every endpoint receives a plaintext credential or a verified identity, so
 * each is validated at **construction**: a deployment configured with an
 * `http://` Store URL fails at boot rather than leaking the first user's
 * password (#285). `http://` is accepted for loopback hosts only — see
 * `src/endpointUrl.mts` for the carve-out and its rationale.
 *
 * No request follows a redirect, so a URL that passed that check is the only
 * place its body is ever sent and the only one whose answer is taken: a `3xx`
 * from the Store is an upstream failure, thrown like any other unexpected
 * status, and its `Location` is never contacted.
 *
 * With `bearerToken` configured, every request — authentication, linking and
 * the identity lookup alike — carries `Authorization: Bearer <token>`, so the
 * Store can refuse a caller that is not this deployment; without it, no
 * request carries an `Authorization` header. The Store says it refused THIS
 * deployment by answering `401` or `403` with a `Bearer` challenge (RFC 6750
 * §3), and that answer, while a token was sent, throws a
 * {@link StoreCredentialRefusedError} on every request — never "no such user"
 * or a refused link, which is what either status without the challenge still
 * means.
 *
 * A transport's own error is never thrown: undici's parser errors quote the
 * bytes they rejected, and a peer that reflects the request puts the
 * `Authorization` header — or a password — there. A request that cannot be
 * made, or an answer that cannot be read, throws a `StoreTransportError`
 * (`src/repositories/storeErrors.mts`): a fixed message naming the endpoint
 * and what failed, at most an allowlisted transport code, no cause.
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
	 * #482 — see {@link UserRepository.linkFederatedIdentity}. Present only when
	 * `linkFederatedIdentityUrl` is configured, which is how the federation routes
	 * know to refuse `?link=1` up front instead of at the callback.
	 */
	readonly linkFederatedIdentity?: (
		userId: string,
		identity: FederatedIdentityLink,
	) => Promise<LinkFederatedIdentityResult>;
	/**
	 * #613 — see {@link UserRepository.supportsFederatedIdentityLookup}. Present
	 * together with the lookup, only when `findSubjectByFederatedIdentityUrl` is
	 * configured: absent, a deployment that requires the lookup is refused at
	 * boot by the method's name, which is the message that says what to set.
	 * Answers from the declaration alone — the Store is not asked at boot.
	 */
	readonly supportsFederatedIdentityLookup?: (
		registration: FederatedIdentityRegistration,
		identityClaims: readonly string[],
	) => boolean;
	/** #613 — see {@link UserRepository.findSubjectByFederatedIdentity}. Present with the probe. */
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
		/** #482: optional; the Store's link endpoint. Same https rule as the other two. */
		linkFederatedIdentityUrl?: string;
		/** #613: optional; the Store's identity lookup. Same https rule; carries a verified identity. */
		findSubjectByFederatedIdentityUrl?: string;
		/** #613: which registrations the Store's lookup covers. Needs the URL; `[]` covers none. */
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
		this.#authorization = bearerAuthorization(bearerToken);
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

		if (!isPositiveIntegerWithin(timeout, MAX_TIMEOUT_MS)) {
			throw new Error(
				`HttpUserRepository: "timeout" must be a positive integer no greater than ` +
					`${MAX_TIMEOUT_MS} milliseconds`,
			);
		}
		this.timeout = timeout;

		if (!isPositiveIntegerWithin(maxResponseBytes, Number.MAX_SAFE_INTEGER)) {
			throw new Error('HttpUserRepository: "maxResponseBytes" must be a positive integer');
		}
		this.maxResponseBytes = maxResponseBytes;
	}

	/** What every request carries: the body's type and, when configured, the credential. */
	private headers(): Record<string, string> {
		return this.#authorization === undefined
			? { "Content-Type": "application/json" }
			: { "Content-Type": "application/json", Authorization: this.#authorization };
	}

	/**
	 * Throws {@link StoreCredentialRefusedError} when a non-`2xx` answer is the
	 * Store refusing this deployment's credential: a `401` or `403` with a
	 * `Bearer` challenge, to a request that carried the token. Read before any
	 * other reading of the status — without it a token the Store does not
	 * accept is every login "no such user" and every link "refused", with
	 * nothing logged. Without a token sent, a challenge is not about one, and a
	 * Store whose stack challenges every refusal keeps the wire meaning it has
	 * always had.
	 */
	private assertCredentialAccepted(res: Response, url: string): void {
		if (
			this.#authorization !== undefined &&
			(res.status === 401 || res.status === 403) &&
			hasBearerChallenge(res.headers.get("www-authenticate"))
		) {
			throw new StoreCredentialRefusedError(url, res.status);
		}
	}

	async authenticate(username: string, password: string): Promise<User | null> {
		// Without `acceptConflict` the sentinel is never produced — a 409 throws.
		return this.post(this.authenticateUrl, { email: username, password }) as Promise<User | null>;
	}

	async authenticateByToken(token: string): Promise<User | null> {
		return this.post(this.authenticateByTokenUrl, { token }) as Promise<User | null>;
	}

	/**
	 * POST `{ userId, provider, sub, token, claims }` to the Store's link endpoint
	 * (#482). A `2xx` `User` is the linked account; `401` / `403` is the Store's
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
	 * (#613) and read one of the port's three answers. Answered locally, with
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
	 * and like it never follows a redirect — the body carries a verified
	 * identity, and a `Location` is not a configured endpoint. None of
	 * {@link post}'s readings, though. A `401`/`403` is not "nobody", a `409` is
	 * not a conflict, a `404` is not an absence: only a `2xx` carrying one of the
	 * three answers is an answer, and everything else throws — as an outage,
	 * which is what a lookup that could not be made is — a `401` or `403` with a
	 * `Bearer` challenge, to a request that carried the token, as the refused
	 * credential it is. What is thrown names the endpoint — and, for an answer
	 * with a status, the status; for a transport failure, at most its code — and
	 * never the body, the identity, a status text or an underlying cause.
	 */
	private async postLookup(url: string, body: unknown): Promise<FederatedIdentityLookupResult> {
		const controller = new AbortController();
		let timedOut = false;
		const timeoutError = (): Error => {
			const error = new Error(
				`HttpUserRepository: request to ${url} timed out after ${this.timeout}ms`,
			);
			error.name = "TimeoutError";
			return error;
		};
		let fireDeadline: () => void = () => {};
		const deadline = new Promise<never>((_resolve, reject) => {
			fireDeadline = () => reject(timeoutError());
		});
		deadline.catch(() => {});
		const timer = setTimeout(() => {
			timedOut = true;
			controller.abort();
			fireDeadline();
		}, this.timeout);

		try {
			let res: Response;
			try {
				res = await fetch(url, {
					method: "POST",
					headers: this.headers(),
					body: JSON.stringify(body),
					signal: controller.signal,
					redirect: "manual",
				});
			} catch (err) {
				if (timedOut && isAbortError(err)) throw timeoutError();
				// A fixed message, without the cause: what a transport reports may
				// quote what it was sending.
				throw requestFailure(err, {
					unreachable: `HttpUserRepository: identity lookup at ${url} could not be reached`,
					notHttp: `HttpUserRepository: identity lookup at ${url} answered something that is not HTTP`,
				});
			}
			if (!res.ok) {
				discardBody(res);
				this.assertCredentialAccepted(res, url);
				throw new Error(
					`HttpUserRepository: identity lookup at ${url} answered HTTP ${res.status}`,
				);
			}
			let raw: string;
			try {
				raw = await readBodyCapped(res, this.maxResponseBytes, url, deadline, (err) =>
					readFailure(err, `HttpUserRepository: identity lookup at ${url} could not be read`),
				);
			} catch (err) {
				if (timedOut) throw timeoutError();
				throw err;
			}
			let parsed: unknown;
			try {
				parsed = JSON.parse(raw);
			} catch {
				throw new Error(`HttpUserRepository: upstream ${url} returned a non-JSON body`);
			}
			const answer = lookupAnswer(parsed);
			if (answer === undefined) {
				throw new Error(
					`HttpUserRepository: identity lookup at ${url} answered a body that is not one of the ` +
						"port's answers (linked / unlinked / indeterminate)",
				);
			}
			return answer;
		} finally {
			clearTimeout(timer);
		}
	}

	private async post(
		url: string,
		body: unknown,
		options: { acceptConflict?: boolean } = {},
	): Promise<User | null | typeof CONFLICT> {
		const controller = new AbortController();
		let timedOut = false;

		// One absolute deadline for the whole exchange, expressed twice: as the
		// abort signal `fetch` understands, and as a promise the body read can be
		// raced against. `.catch` is attached up front so an exchange that
		// finishes first — the overwhelmingly common case, where the timer is
		// cleared and this never rejects — cannot leave an unhandled rejection.
		// Named as the lookup's is: a reporter that classifies by `name` —
		// federation-grants' reads `TimeoutError` as `timeout` — sees one kind
		// of timeout whichever request it came from.
		const timeoutError = (): Error => {
			const error = new Error(
				`HttpUserRepository: request to ${url} timed out after ${this.timeout}ms`,
			);
			error.name = "TimeoutError";
			return error;
		};
		let fireDeadline: () => void = () => {};
		const deadline = new Promise<never>((_resolve, reject) => {
			fireDeadline = () => reject(timeoutError());
		});
		deadline.catch(() => {});

		const timer = setTimeout(() => {
			timedOut = true;
			controller.abort();
			fireDeadline();
		}, this.timeout);

		try {
			let res: Response;
			try {
				res = await fetch(url, {
					method: "POST",
					headers: this.headers(),
					body: JSON.stringify(body),
					signal: controller.signal,
					// Never followed: a 307 or 308 would re-send the body — a
					// password, a token, a link request — to a `Location` the https
					// rule never checked, and after any redirect the answer from
					// there would be taken as the user. Node's fetch hands the 3xx
					// back as it is (a browser-spec runtime would hand back an opaque
					// redirect, status 0); either way it is not a 2xx, 401, 403 or
					// 409, so it throws below as an unexpected status.
					redirect: "manual",
				});
			} catch (err) {
				if (timedOut && isAbortError(err)) throw timeoutError();
				// Never the transport's own error: it may quote what it was
				// sending — the credential, the password — or what came back.
				throw requestFailure(err, {
					unreachable: `HttpUserRepository: request to ${url} could not be reached`,
					notHttp: `HttpUserRepository: the Store at ${url} answered something that is not HTTP`,
				});
			}

			if (res.ok) {
				let raw: string;
				try {
					raw = await readBodyCapped(res, this.maxResponseBytes, url, deadline, (err) =>
						readFailure(err, `HttpUserRepository: response from ${url} could not be read`),
					);
				} catch (err) {
					// Whatever the deadline interrupted is a timeout; everything
					// else readBodyCapped throws is already the adapter's own.
					if (timedOut) throw timeoutError();
					throw err;
				}
				let parsed: unknown;
				try {
					parsed = JSON.parse(raw);
				} catch {
					// Same class of failure as the shape check below: the Store is
					// broken, not the credential. Reported as ours rather than as a
					// bare SyntaxError with no indication of where it came from.
					throw new Error(`HttpUserRepository: upstream ${url} returned a non-JSON body`);
				}
				if (!isUser(parsed)) {
					// Upstream returned 2xx with an unexpected shape — this is an
					// "upstream is broken" case, not a "user not found" case, so
					// throw rather than return null. The thrown error propagates
					// as a 500 to the client (correct: upstream-service failure).
					throw new Error(`HttpUserRepository: upstream ${url} returned an invalid User shape`);
				}
				return parsed;
			}

			discardBody(res);
			this.assertCredentialAccepted(res, url);

			if (options.acceptConflict && res.status === 409) {
				return CONFLICT;
			}
			if (res.status === 401 || res.status === 403) {
				return null;
			}

			throw new Error(`Unexpected HTTP status ${res.status} from ${url}`);
		} finally {
			clearTimeout(timer);
		}
	}
}
