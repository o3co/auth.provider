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

import type { User, UserRepository } from "@o3co/auth-provider-core";
import { assertSecureEndpoint } from "../endpointUrl.mjs";

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
 */
async function readBodyCapped(
	res: Response,
	limit: number,
	url: string,
	deadline: Promise<never>,
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
			const { done, value } = await Promise.race([reader.read(), deadline]);
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
 * still fails — it would simply surface the runtime's message instead of ours,
 * which is a cosmetic difference and not worth an untestable `cause` walk.
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
 * on core's `User` doc (`@o3co/auth-provider-core`, `repositories/types.mts`).
 *
 * Both endpoints receive plaintext user credentials, so both are validated at
 * **construction**: a deployment configured with an `http://` Store URL fails
 * at boot rather than leaking the first user's password (#285). `http://` is
 * accepted for loopback hosts only — see `src/endpointUrl.mts` for the
 * carve-out and its rationale.
 */
export class HttpUserRepository implements UserRepository {
	private authenticateUrl: string;
	private authenticateByTokenUrl: string;
	private timeout: number;
	private maxResponseBytes: number;

	constructor({
		authenticateUrl,
		authenticateByTokenUrl,
		timeout,
		maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
	}: {
		authenticateUrl: string;
		authenticateByTokenUrl: string;
		timeout: number;
		maxResponseBytes?: number;
	}) {
		this.authenticateUrl = assertSecureEndpoint(authenticateUrl, "authenticateUrl");
		this.authenticateByTokenUrl = assertSecureEndpoint(
			authenticateByTokenUrl,
			"authenticateByTokenUrl",
		);

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

	async authenticate(username: string, password: string): Promise<User | null> {
		return this.post(this.authenticateUrl, { email: username, password });
	}

	async authenticateByToken(token: string): Promise<User | null> {
		return this.post(this.authenticateByTokenUrl, { token });
	}

	private async post(url: string, body: unknown): Promise<User | null> {
		const controller = new AbortController();
		let timedOut = false;

		// One absolute deadline for the whole exchange, expressed twice: as the
		// abort signal `fetch` understands, and as a promise the body read can be
		// raced against. `.catch` is attached up front so an exchange that
		// finishes first — the overwhelmingly common case, where the timer is
		// cleared and this never rejects — cannot leave an unhandled rejection.
		let fireDeadline: () => void = () => {};
		const deadline = new Promise<never>((_resolve, reject) => {
			fireDeadline = () =>
				reject(
					new Error(`HttpUserRepository: request to ${url} timed out after ${this.timeout}ms`),
				);
		});
		deadline.catch(() => {});

		const timer = setTimeout(() => {
			timedOut = true;
			controller.abort();
			fireDeadline();
		}, this.timeout);

		try {
			const res = await fetch(url, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(body),
				signal: controller.signal,
			});

			if (res.ok) {
				const raw = await readBodyCapped(res, this.maxResponseBytes, url, deadline);
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

			if (res.status === 401 || res.status === 403) {
				return null;
			}

			throw new Error(`Unexpected HTTP status ${res.status} from ${url}`);
		} catch (err) {
			if (timedOut && isAbortError(err)) {
				throw new Error(`HttpUserRepository: request to ${url} timed out after ${this.timeout}ms`);
			}
			throw err;
		} finally {
			clearTimeout(timer);
		}
	}
}
