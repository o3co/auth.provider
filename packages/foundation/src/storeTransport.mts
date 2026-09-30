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

/**
 * The transport every request to the Store rides on: the credential it
 * presents, the deadline, the response cap, and a `POST` of JSON that
 * follows no redirect.
 *
 * Guarantees: a setting the transport cannot honour is refused when the
 * client is built, naming the setting and quoting no value; one deadline
 * covers a whole exchange, the body read included; a body is read up to the
 * cap and no further, and a body not read is released unawaited; what is
 * thrown is the adapter's own — never a transport's error, which may quote
 * the request — and names an endpoint by origin and path alone.
 */

import {
	describeWeakSecret,
	MIN_SECRET_ENTROPY_BYTES,
	measureSecretEntropyBytes,
} from "@o3co/auth-provider-core";
import { endpointForMessage } from "./endpointUrl.mjs";
import {
	readFailure,
	requestFailure,
	StoreCredentialRefusedError,
} from "./repositories/storeErrors.mjs";
import { hasBearerChallenge } from "./repositories/wwwAuthenticate.mjs";

/**
 * Default ceiling on an upstream response body, in bytes.
 *
 * A `User` record is a few hundred bytes; 1 MiB is generous for one carrying
 * custom claims and small enough that a hostile or broken Store cannot walk the
 * process out of memory one login at a time.
 */
export const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;

/** Default request deadline, in milliseconds, when the configuration names none. */
const DEFAULT_TIMEOUT_MS = 5000;

/**
 * Largest delay Node's timer subsystem represents. Anything above it is
 * silently clamped to 1ms — so an operator writing a very large number meaning
 * "be patient" would otherwise get the most impatient timeout possible.
 */
const MAX_TIMEOUT_MS = 2_147_483_647;

/**
 * RFC 6750 §2.1 `b64token` — the characters a bearer credential may carry.
 * Nothing in it is whitespace or a control character, so a token that
 * matches cannot break the header it rides in.
 */
const B64TOKEN = /^[A-Za-z0-9\-._~+/]+=*$/;

const BEARER_TOKEN_FIELD = "bearerToken";

/**
 * The credential presented to the Store, checked when `owner` is built (so
 * an unusable one fails at boot) and turned into the `Authorization` value;
 * `undefined` when none is configured, which sends no `Authorization` header.
 *
 * The shape is refused here, not left to `fetch`, which QUOTES a header value
 * it refuses in the `TypeError` it throws, where the session routes log it.
 * The strength is core's shared-secret floor (`MIN_SECRET_ENTROPY_BYTES`, on
 * the decoded length): whoever holds this token speaks to the Store as
 * auth.provider. No message quotes the value.
 */
export function bearerAuthorization(value: unknown, owner: string): string | undefined {
	if (value === undefined) return undefined;
	const refuse = (problem: string): Error =>
		new Error(`${owner}: "${BEARER_TOKEN_FIELD}" ${problem}`);
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
			`${owner}: ${describeWeakSecret(actualBytes, {
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

/** `timeout`, the whole exchange's deadline in milliseconds, or an error naming it for `owner`. */
export function checkStoreTimeout(timeout: unknown, owner: string): number {
	if (!isPositiveIntegerWithin(timeout, MAX_TIMEOUT_MS)) {
		throw new Error(
			`${owner}: "timeout" must be a positive integer no greater than ` +
				`${MAX_TIMEOUT_MS} milliseconds`,
		);
	}
	return timeout;
}

/** `maxResponseBytes`, the response cap, or an error naming it for `owner`. */
export function checkStoreResponseCap(maxResponseBytes: unknown, owner: string): number {
	if (!isPositiveIntegerWithin(maxResponseBytes, Number.MAX_SAFE_INTEGER)) {
		throw new Error(`${owner}: "maxResponseBytes" must be a positive integer`);
	}
	return maxResponseBytes;
}

/**
 * Coerces a numeric config value that may arrive as a string (HOCON
 * environment substitution yields strings). Only an *absent* key takes
 * `fallback`. Anything present but unreadable becomes `NaN` for the
 * constructor to reject, and a **blank** environment variable, which HOCON
 * substitutes as `""`, becomes `0`: a boot failure too, not a silent default.
 */
const toNumber = (value: unknown, fallback: number): number => {
	if (value === undefined || value === null) return fallback;
	if (typeof value === "number") return value;
	if (typeof value === "string") return Number(value.trim());
	return Number.NaN;
};

/**
 * The transport settings of a Store client's configuration block — the user
 * repository's `http` block — as a client is built from them: `timeout` and
 * `maxResponseBytes` read from text too and defaulted only when absent, and
 * `bearerToken` forwarded whenever set, whatever it holds. The client's
 * constructor refuses what the transport cannot honour.
 */
export function readStoreTransportConfig(block: Readonly<Record<string, unknown>>): {
	readonly bearerToken?: string;
	readonly timeout: number;
	readonly maxResponseBytes: number;
} {
	return {
		// Forwarded whenever SET, not only when well-typed: a token that vanished
		// would be a deployment that believes its Store calls authenticated and
		// sends them bare.
		...(block.bearerToken !== undefined ? { bearerToken: block.bearerToken as string } : {}),
		timeout: toNumber(block.timeout, DEFAULT_TIMEOUT_MS),
		maxResponseBytes: toNumber(block.maxResponseBytes, DEFAULT_MAX_RESPONSE_BYTES),
	};
}

/**
 * Releases a response body we are not going to read. Left unconsumed, undici
 * holds the socket until the response is garbage collected instead of
 * returning it to the keep-alive pool: a slow leak on the failure path.
 *
 * Deliberately not awaited: that would hand a hostile Store a second way to
 * stall the caller, the one the request deadline exists to close, and some
 * interceptors never settle it at all.
 */
export function discardBody(res: Response): void {
	res.body?.cancel().catch(() => {
		// Already consumed, already errored, or aborted — nothing to release.
	});
}

/**
 * Reads at most `limit` bytes of `res` as text, throwing once it is passed.
 * `Content-Length` refuses an honest oversized response before a byte is read,
 * but the streaming count is the load-bearing half: a hostile Store omits the
 * header or lies, and chunked encoding has none. Everything it throws is the
 * adapter's own (the cap, the deadline's rejection, what `unreadable` makes of
 * a transport error mid-read), never the transport's error as it is.
 */
export async function readBodyCapped(
	res: Response,
	limit: number,
	endpoint: string,
	deadline: Promise<never>,
	unreadable: (err: unknown) => Error,
	owner: string,
): Promise<string> {
	const declared = Number(res.headers.get("content-length"));
	if (Number.isFinite(declared) && declared > limit) {
		discardBody(res);
		throw new Error(
			`${owner}: upstream ${endpoint} response exceeds the ${limit}-byte cap ` +
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
				throw new Error(`${owner}: upstream ${endpoint} response exceeds the ${limit}-byte cap`);
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
 * Whether `err` is the abort our own deadline raised on the `fetch` itself,
 * where the response headers never arrive. Deliberately shallow: an aborted
 * `fetch` rejects with the `AbortError` directly. A runtime that wrapped one
 * would still fail the request, as a `StoreTransportError` rather than a
 * `TimeoutError`: misnamed, not missed. A stalled *body* is the deadline race
 * in `readBodyCapped`.
 */
export function isAbortError(err: unknown): boolean {
	// Optional chaining rather than a `typeof` guard: it covers `null`,
	// `undefined` and a thrown primitive in the same expression, with no
	// branch that only a contrived throw could reach.
	const name = (err as { name?: unknown } | null | undefined)?.name;
	return name === "AbortError" || name === "TimeoutError";
}

/** What a request to the Store is sent with. */
export interface StoreRequestSettings {
	/** `Bearer <token>`, or `undefined` to send no `Authorization` header. */
	readonly authorization: string | undefined;
	/** The whole exchange's deadline, in milliseconds. */
	readonly timeout: number;
	/** The most bytes of a body read. */
	readonly maxResponseBytes: number;
}

/** What a failure of the exchange says, each naming the endpoint. */
export interface StoreRequestMessages {
	/** Who is asking, leading every message. */
	readonly owner: string;
	readonly unreachable: string;
	readonly closed: string;
	readonly malformed: string;
	readonly unreadable: string;
}

/** An answer: the response, whose body is released, and the body as text when it was read. */
export interface StoreAnswer {
	readonly response: Response;
	readonly text: string | undefined;
}

/**
 * `POST`s `body` as JSON to `url` and answers what came back, the body read
 * (up to the cap, within the deadline) only when `readsBody` says so for the
 * status, and released otherwise. A `401` or `403` with a `Bearer` challenge
 * to a request that carried the credential throws
 * `StoreCredentialRefusedError`; a deadline passed throws an error named
 * `TimeoutError`; a transport failure throws a `StoreTransportError`.
 */
export async function postToStore(
	url: string,
	body: unknown,
	settings: StoreRequestSettings,
	messages: StoreRequestMessages,
	readsBody: (status: number) => boolean,
): Promise<StoreAnswer> {
	const endpoint = endpointForMessage(url);
	const controller = new AbortController();
	let timedOut = false;
	const timeoutError = (): Error => {
		const error = new Error(
			`${messages.owner}: request to ${endpoint} timed out after ${settings.timeout}ms`,
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
	}, settings.timeout);

	try {
		let response: Response;
		try {
			response = await fetch(url, {
				method: "POST",
				headers:
					settings.authorization === undefined
						? { "Content-Type": "application/json" }
						: { "Content-Type": "application/json", Authorization: settings.authorization },
				body: JSON.stringify(body),
				signal: controller.signal,
				// Never followed: a redirect would re-send the body to a `Location`
				// no endpoint check has seen, and take its answer as the Store's.
				redirect: "manual",
			});
		} catch (err) {
			if (timedOut && isAbortError(err)) throw timeoutError();
			throw requestFailure(err, messages);
		}
		if (!readsBody(response.status)) {
			discardBody(response);
			if (
				settings.authorization !== undefined &&
				(response.status === 401 || response.status === 403) &&
				hasBearerChallenge(response.headers.get("www-authenticate"))
			) {
				throw new StoreCredentialRefusedError(url, response.status);
			}
			return { response, text: undefined };
		}
		try {
			const text = await readBodyCapped(
				response,
				settings.maxResponseBytes,
				endpoint,
				deadline,
				(err) => readFailure(err, messages.unreadable),
				messages.owner,
			);
			return { response, text };
		} catch (err) {
			if (timedOut) throw timeoutError();
			throw err;
		}
	} finally {
		clearTimeout(timer);
	}
}
