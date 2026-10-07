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
 * The outbound fetch: a `fetch` for every URL a client registration or a
 * request supplies, which only reaches what `core.outbound` admits. It reads
 * the section (the one reader of `core.outbound`), or takes the policy that
 * reader answered (the `outboundPolicy` slot), resolves the host once,
 * checks every address (`outbound-policy.mts`), connects only to the checked
 * addresses (`outbound-transport.mts`), refuses redirects and encoded
 * answers, reads a 2xx body under a cap, and holds the whole exchange to one
 * deadline. A caller sees a `fetch`, and tells a refusal from a failure with
 * `isOutboundRefusal` alone. `outboundLimitsOf` answers the deadline and cap
 * `core.outbound` sets, the ceilings over every use's own.
 */

import { lookup as dnsLookup } from "node:dns/promises";
import {
	type AdmittedDestination,
	admitAddresses,
	admitUrl,
	MAX_TIMEOUT_MS,
	OutboundFetchError,
	type OutboundPolicy,
	OutboundSectionSchema,
	type OutboundUrlSource,
	readHostEntry,
} from "./outbound-policy.mjs";
import {
	nodeTransport,
	type OutboundAnswer,
	type OutboundExchange,
	type OutboundTransport,
} from "./outbound-transport.mjs";

export type { OutboundUrlSource } from "./outbound-policy.mjs";

/** What a fetch is built for, beside the policy it follows. */
interface OutboundFetchUse {
	/**
	 * Where the URLs this fetch is handed come from: `"registration"` (a
	 * client registration) may use `core.outbound.internalHosts`;
	 * `"request"` (a URL a request names) never does.
	 */
	readonly source: OutboundUrlSource;
	/** This use's deadline in milliseconds, at most `core.outbound.timeoutMs` (the smaller applies). */
	readonly timeoutMs?: number;
	/** This use's cap on a 2xx body in bytes, at most `core.outbound.maxResponseBytes` (the smaller applies). */
	readonly maxResponseBytes?: number;
}

/**
 * The policy a fetch follows, given exactly one way: `config`, the
 * composition's configuration, whose `core.outbound` is read (an absent
 * section reads as the defaults), or `policy`, the policy core read from it
 * (the `outboundPolicy` slot).
 */
export type OutboundFetchOptions = OutboundFetchUse &
	(
		| { readonly config: unknown; readonly policy?: undefined }
		| { readonly policy: OutboundPolicy; readonly config?: undefined }
	);

/**
 * The seams below the policy: name resolution, the places it is run under
 * (`lookups`, the process-wide pool for the public factory), and the exchange.
 */
export interface OutboundFetchSeams {
	readonly lookup: (hostname: string) => Promise<readonly string[]>;
	readonly lookups: LookupPermits;
	readonly transport: OutboundTransport;
}

/** Every address the system resolver answers for `hostname`, both families, in its order. */
export const systemLookup = async (hostname: string): Promise<readonly string[]> =>
	(await dnsLookup(hostname, { all: true, order: "verbatim" })).map((entry) => entry.address);

/** libuv's own threadpool size when `UV_THREADPOOL_SIZE` does not set one. */
const DEFAULT_THREADPOOL_SIZE = 4;

/**
 * How many host-name resolutions the process may have outstanding, for a
 * threadpool size as `UV_THREADPOOL_SIZE` gives it (an integer from 1 to
 * 1024; anything else reads as libuv's default, 4): two fewer than the
 * threadpool, and at least one. The system resolver runs on that threadpool,
 * which bcrypt and the file system share, and it cannot be cancelled: a
 * lookup the deadline gave up on keeps a thread until it settles. Keeping
 * the bound below the threadpool leaves threads for the rest however slow
 * name resolution gets.
 */
export function lookupCeilingOf(threadpoolSize: string | undefined): number {
	const raw = (threadpoolSize ?? "").trim();
	const size = /^\d{1,4}$/.test(raw) ? Number(raw) : Number.NaN;
	const threads = size >= 1 && size <= 1024 ? size : DEFAULT_THREADPOOL_SIZE;
	return Math.max(1, threads - 2);
}

/**
 * How many calls may wait for a place among the outstanding lookups. A call
 * that finds this many already waiting fails with `timeout` at once, without
 * waiting and without starting a lookup: each waiter holds a listener and its
 * call's deadline, so the queue is bounded as the lookups are. Fixed, not
 * configured.
 */
export const MAX_WAITING_LOOKUPS = 64;

/** No place among the outstanding lookups, and no room to wait for one. */
class LookupsSaturated extends Error {}

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024;

const patterns = (entries: readonly string[] | undefined) =>
	Object.freeze(
		(entries ?? []).map((entry) => {
			const pattern = readHostEntry(entry);
			// The schema has refused every entry this would not read.
			if (pattern === undefined) throw new Error(`core.outbound: unreadable host entry`);
			return Object.freeze(pattern);
		}),
	);

/**
 * The policy `config` states in `core.outbound`: an absent section (or no
 * configuration) reads as the defaults; a present one is validated and
 * refused, naming the key, when it does not parse. Frozen all the way down.
 */
export function outboundPolicyOf(config: unknown): OutboundPolicy {
	const core = (config as { core?: unknown } | null | undefined)?.core;
	const section =
		typeof core === "object" && core !== null && Object.hasOwn(core, "outbound")
			? (core as { outbound: unknown }).outbound
			: undefined;
	const parsed = OutboundSectionSchema.safeParse(section === undefined ? {} : section);
	if (!parsed.success) {
		const problems = parsed.error.issues.map(
			(issue) =>
				`core.outbound${issue.path.length > 0 ? `.${issue.path.join(".")}` : ""}: ${issue.message}`,
		);
		throw new Error(`core.outbound is malformed: ${problems.join("; ")}`);
	}
	return Object.freeze({
		allowedHosts: patterns(parsed.data.allowedHosts),
		deniedHosts: patterns(parsed.data.deniedHosts),
		internalHosts: patterns(parsed.data.internalHosts),
		timeoutMs: parsed.data.timeoutMs ?? DEFAULT_TIMEOUT_MS,
		maxResponseBytes: parsed.data.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
		egress: parsed.data.egress,
	});
}

/** The deadline and the body cap `core.outbound` sets: the ceilings over every use's own. */
export interface OutboundLimits {
	readonly timeoutMs: number;
	readonly maxResponseBytes: number;
}

/**
 * The limits `config` states in `core.outbound`, as the outbound fetch
 * applies them (the defaults for an absent section). Refuses a malformed
 * section, naming the key, as building the fetch does.
 */
export function outboundLimitsOf(config: unknown): OutboundLimits {
	const { timeoutMs, maxResponseBytes } = outboundPolicyOf(config);
	return Object.freeze({ timeoutMs, maxResponseBytes });
}

const PROXY_VARIABLES = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] as const;

/**
 * The environment variable that configures an egress proxy, if one does. A
 * fetch dispatcher installed in code is not consulted: this fetch never
 * connects through it.
 */
const configuredProxy = (): string | undefined =>
	PROXY_VARIABLES.find((variable) => (process.env[variable] ?? "").trim() !== "");

const positiveWholeNumber = (
	value: number | undefined,
	name: string,
	max = Number.MAX_SAFE_INTEGER,
): number | undefined => {
	if (value === undefined) return undefined;
	if (!Number.isSafeInteger(value) || value <= 0 || value > max) {
		throw new TypeError(`createOutboundFetch: ${name} must be a whole number from 1 to ${max}`);
	}
	return value;
};

/** Headers the transport writes itself; a caller's are dropped. */
const TRANSPORT_HEADERS: ReadonlySet<string> = new Set([
	"accept-encoding",
	"connection",
	"content-length",
	"expect",
	"host",
	"keep-alive",
	"proxy-connection",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
]);

interface OutboundRequest {
	readonly url: string;
	readonly method: "GET" | "POST";
	readonly headers: Readonly<Record<string, string>>;
	readonly body: Uint8Array | undefined;
}

/** `input` and `init` as this fetch supports them; a `TypeError` for anything else. */
function readRequest(input: unknown, init: RequestInit | undefined): OutboundRequest {
	if (typeof input !== "string" && !(input instanceof URL)) {
		throw new TypeError("outbound fetch takes a string or a URL");
	}
	const method = (init?.method ?? "GET").toUpperCase();
	if (method !== "GET" && method !== "POST") {
		throw new TypeError("outbound fetch sends GET or POST");
	}
	const raw = init?.body ?? undefined;
	let body: Uint8Array | undefined;
	let contentType: string | undefined;
	if (typeof raw === "string") {
		body = new TextEncoder().encode(raw);
		contentType = "text/plain;charset=UTF-8";
	} else if (raw instanceof URLSearchParams) {
		body = new TextEncoder().encode(raw.toString());
		contentType = "application/x-www-form-urlencoded;charset=UTF-8";
	} else if (raw instanceof Uint8Array) {
		body = new Uint8Array(raw);
	} else if (raw !== undefined) {
		throw new TypeError("outbound fetch sends a string, URLSearchParams or Uint8Array body");
	}
	if (method === "GET" && body !== undefined) {
		throw new TypeError("outbound fetch sends no body with GET");
	}
	const headers: Record<string, string> = {};
	for (const [name, value] of new Headers(init?.headers)) {
		if (!TRANSPORT_HEADERS.has(name)) headers[name] = value;
	}
	if (contentType !== undefined && headers["content-type"] === undefined) {
		headers["content-type"] = contentType;
	}
	if (method === "POST") headers["content-length"] = String(body?.byteLength ?? 0);
	headers["accept-encoding"] = "identity";
	return { url: typeof input === "string" ? input : input.href, method, headers, body };
}

/**
 * `promise`, or `signal`'s reason once it aborts, whichever comes first.
 * `promise` is observed on every path, so its own rejection after an abort
 * is never left unhandled.
 */
const untilAborted = <T,>(promise: Promise<T>, signal: AbortSignal): Promise<T> =>
	new Promise<T>((resolve, reject) => {
		const onAbort = () => reject(signal.reason);
		promise.then(
			(value) => {
				signal.removeEventListener("abort", onAbort);
				resolve(value);
			},
			(err: unknown) => {
				signal.removeEventListener("abort", onAbort);
				reject(err);
			},
		);
		if (signal.aborted) onAbort();
		else signal.addEventListener("abort", onAbort, { once: true });
	});

/** Lookups run under a bounded number of places; see {@link createLookupPermits}. */
export type LookupPermits = (
	lookup: OutboundFetchSeams["lookup"],
	hostname: string,
	signal: AbortSignal,
) => Promise<readonly string[]>;

/**
 * A pool of places for outstanding lookups, bounded at `max`,
 * with at most `maxWaiting` calls waiting for a place. A permit is taken
 * before a lookup starts and given back only when the lookup settles; a
 * waiter is handed the permit directly, in arrival order. The waiters are a
 * `Set`, which iterates in insertion order and drops a cancelled one in
 * constant time.
 */
export function createLookupPermits(max: number, maxWaiting: number): LookupPermits {
	let outstanding = 0;
	const waiters = new Set<() => void>();
	const release = (): void => {
		const next = waiters.values().next();
		if (next.done === true) {
			outstanding -= 1;
			return;
		}
		waiters.delete(next.value);
		next.value();
	};
	/**
	 * A permit; `signal`'s reason once it aborts first, or `LookupsSaturated`
	 * when no one more may wait. No permit is held in either case.
	 */
	const acquire = (signal: AbortSignal): Promise<void> => {
		signal.throwIfAborted();
		if (outstanding < max) {
			outstanding += 1;
			return Promise.resolve();
		}
		if (waiters.size >= maxWaiting) throw new LookupsSaturated();
		return new Promise<void>((resolve, reject) => {
			const onAbort = () => {
				waiters.delete(granted);
				reject(signal.reason);
			};
			const granted = () => {
				signal.removeEventListener("abort", onAbort);
				resolve();
			};
			waiters.add(granted);
			signal.addEventListener("abort", onAbort, { once: true });
		});
	};
	/**
	 * `lookup(hostname)` under a permit, or `signal`'s reason with no lookup
	 * started. The permit is given back when the lookup settles, however long
	 * after the call stopped waiting for it.
	 */
	return async (
		lookup: OutboundFetchSeams["lookup"],
		hostname: string,
		signal: AbortSignal,
	): Promise<readonly string[]> => {
		await acquire(signal);
		if (signal.aborted) {
			// Handed a permit after the deadline: no lookup is started on it.
			release();
			throw signal.reason;
		}
		let looking: Promise<readonly string[]>;
		try {
			looking = lookup(hostname);
		} catch (err) {
			looking = Promise.reject(err);
		}
		looking.then(release, release);
		return looking;
	};
}

/**
 * The places every fetch `createOutboundFetch` builds resolves under, one
 * pool for the process: `UV_THREADPOOL_SIZE` is read once, here, as libuv
 * reads it once at its first use of the threadpool.
 */
const processLookups = createLookupPermits(
	lookupCeilingOf(process.env.UV_THREADPOOL_SIZE),
	MAX_WAITING_LOOKUPS,
);

/** The answer's body, read whole under `cap`; a refusal past it. */
async function readBody(
	answer: OutboundAnswer,
	cap: number,
	host: string,
	signal: AbortSignal,
): Promise<Uint8Array> {
	const chunks: Uint8Array[] = [];
	let length = 0;
	const iterator = answer.body[Symbol.asyncIterator]();
	for (;;) {
		const next = await untilAborted(iterator.next(), signal);
		if (next.done === true) break;
		length += next.value.byteLength;
		if (length > cap) throw new OutboundFetchError("response_too_large", host);
		chunks.push(next.value);
	}
	const body = new Uint8Array(length);
	let offset = 0;
	for (const chunk of chunks) {
		body.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return body;
}

type ResponseBody = ConstructorParameters<typeof Response>[0];

const NULL_BODY_STATUSES: ReadonlySet<number> = new Set([204, 205, 304]);

/**
 * The `Response` for `answer`, its status classified before any body is
 * read: a redirect (any 3xx but 304) is refused; a status that carries no
 * body, or is not 2xx, gets a null body without reading or waiting for it;
 * a 2xx body is read only in the identity encoding and under the cap.
 */
async function respond(
	answer: OutboundAnswer,
	destination: AdmittedDestination,
	cap: number,
	signal: AbortSignal,
): Promise<Response> {
	const { status } = answer;
	if (status >= 300 && status < 400 && status !== 304) {
		throw new OutboundFetchError("redirect_refused", destination.host);
	}
	const headers = new Headers();
	for (const [name, value] of answer.headers) {
		try {
			headers.append(name, value);
		} catch {
			// A header the Fetch API cannot hold is not handed on.
		}
	}
	let body: Uint8Array | null = null;
	if (status >= 200 && status < 300 && !NULL_BODY_STATUSES.has(status)) {
		const encoding = headers.get("content-encoding");
		if (encoding !== null && encoding.trim().toLowerCase() !== "identity") {
			throw new OutboundFetchError("unsupported_encoding", destination.host);
		}
		const declared = headers.get("content-length");
		if (declared !== null && /^\d+$/.test(declared.trim()) && Number(declared) > cap) {
			throw new OutboundFetchError("response_too_large", destination.host);
		}
		body = await readBody(answer, cap, destination.host, signal);
	}
	const init = { status, headers };
	try {
		return new Response(body as ResponseBody, { ...init, statusText: answer.statusText });
	} catch {
		// A reason phrase the Fetch API refuses is dropped, not the answer.
		return new Response(body as ResponseBody, init);
	}
}

/** A Node error code, which names a failure without quoting the peer. */
const errorCode = (err: unknown): string | undefined => {
	const code = (err as { code?: unknown } | null | undefined)?.code;
	return typeof code === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(code) ? code : undefined;
};

/** Whether `value` is a list of host patterns, as the reader answers one. */
const isPatternList = (value: unknown): boolean =>
	Array.isArray(value) &&
	value.every((pattern: unknown) => {
		const { host, suffix } = (pattern ?? {}) as { host?: unknown; suffix?: unknown };
		return typeof host === "string" && host.length > 0 && typeof suffix === "boolean";
	});

/**
 * The member of `policy` that breaks the shape `outboundPolicyOf` answers,
 * or `undefined` when none does: a broken limit would lift the deadline or
 * the body cap rather than apply it.
 */
function brokenPolicyMember(policy: Readonly<Record<string, unknown>>): string | undefined {
	for (const list of ["allowedHosts", "deniedHosts", "internalHosts"]) {
		if (!isPatternList(policy[list])) return list;
	}
	const { timeoutMs, maxResponseBytes, egress } = policy;
	if (
		!Number.isSafeInteger(timeoutMs) ||
		(timeoutMs as number) < 1 ||
		(timeoutMs as number) > MAX_TIMEOUT_MS
	) {
		return "timeoutMs";
	}
	if (!Number.isSafeInteger(maxResponseBytes) || (maxResponseBytes as number) < 1) {
		return "maxResponseBytes";
	}
	if (egress !== undefined && egress !== "direct") return "egress";
	return undefined;
}

/** The policy `options` gives, by exactly one of `config` and `policy`; a `TypeError` otherwise. */
function policyFrom(options: OutboundFetchOptions): OutboundPolicy {
	const { config, policy } = options as { config?: unknown; policy?: unknown };
	if ((config === undefined) === (policy === undefined)) {
		throw new TypeError("createOutboundFetch: give exactly one of config and policy");
	}
	if (policy === undefined) return outboundPolicyOf(config);
	if (typeof policy !== "object" || policy === null) {
		throw new TypeError("createOutboundFetch: policy must be an OutboundPolicy");
	}
	const broken = brokenPolicyMember(policy as Readonly<Record<string, unknown>>);
	if (broken !== undefined) {
		throw new TypeError(
			`createOutboundFetch: policy.${broken} is not as outboundPolicyOf answers it`,
		);
	}
	return policy as OutboundPolicy;
}

/**
 * The outbound fetch over `seams`. The public factory passes the system
 * resolver and Node's transport; the testing entry passes its own.
 */
export function buildOutboundFetch(
	options: OutboundFetchOptions,
	seams: OutboundFetchSeams,
): typeof fetch {
	const source = (options as { source?: unknown } | undefined)?.source;
	if (source !== "registration" && source !== "request") {
		throw new TypeError('createOutboundFetch: source must be "registration" or "request"');
	}
	const policy = policyFrom(options);
	const proxy = configuredProxy();
	if (proxy !== undefined && policy.egress !== "direct") {
		throw new Error(
			`core.outbound: ${proxy} configures an egress proxy, and the outbound fetch connects ` +
				'directly; set core.outbound.egress = "direct" (CORE_OUTBOUND_EGRESS) to state that ' +
				"direct egress is intended",
		);
	}
	// `core.outbound` is a ceiling: a use may shorten the deadline or lower the cap, never raise them.
	const timeoutMs = Math.min(
		positiveWholeNumber(options.timeoutMs, "timeoutMs", MAX_TIMEOUT_MS) ?? policy.timeoutMs,
		policy.timeoutMs,
	);
	const cap = Math.min(
		positiveWholeNumber(options.maxResponseBytes, "maxResponseBytes") ?? policy.maxResponseBytes,
		policy.maxResponseBytes,
	);

	const outboundFetch = async (input: unknown, init?: RequestInit): Promise<Response> => {
		const request = readRequest(input, init);
		const callerSignal = init?.signal ?? undefined;
		callerSignal?.throwIfAborted();
		const deadline = new AbortController();
		const timer = setTimeout(() => deadline.abort(), timeoutMs);
		const signal =
			callerSignal === undefined
				? deadline.signal
				: AbortSignal.any([callerSignal, deadline.signal]);
		let host: string | undefined;
		let answer: OutboundAnswer | undefined;
		try {
			const destination = admitUrl(request.url, policy, source);
			host = destination.host;
			let addresses: readonly string[];
			if (destination.literal !== undefined) {
				addresses = [destination.literal];
			} else {
				const resolving = seams
					.lookups(seams.lookup, destination.url.hostname, signal)
					.catch((err: unknown) => {
						if (err instanceof LookupsSaturated) {
							throw new OutboundFetchError("timeout", destination.host);
						}
						throw new OutboundFetchError("resolution_failed", destination.host, errorCode(err));
					});
				addresses = await untilAborted(resolving, signal);
				admitAddresses(destination, addresses);
			}
			const exchange: OutboundExchange = {
				url: destination.url,
				servername: destination.literal === undefined ? destination.host : undefined,
				addresses,
				method: request.method,
				headers: request.headers,
				body: request.body,
				signal,
			};
			const answering = seams.transport(exchange);
			// An answer that arrives after the deadline is still released.
			answering.then(
				(late) => {
					if (signal.aborted) late.close();
				},
				() => undefined,
			);
			answer = await untilAborted(answering, signal);
			return await respond(answer, destination, cap, signal);
		} catch (err) {
			if (callerSignal?.aborted === true) throw callerSignal.reason;
			if (deadline.signal.aborted) throw new OutboundFetchError("timeout", host);
			if (err instanceof OutboundFetchError) throw err;
			throw new OutboundFetchError("network_error", host, errorCode(err));
		} finally {
			clearTimeout(timer);
			answer?.close();
		}
	};
	return outboundFetch as typeof fetch;
}

/**
 * A `fetch` that only reaches destinations `core.outbound` admits, for URLs
 * from `options.source`, read from `options.config` or given as
 * `options.policy`. Throws a `TypeError` unless exactly one of the two is
 * given, an `Error` when `core.outbound` is malformed, and when
 * `HTTPS_PROXY` or `HTTP_PROXY` is set without `core.outbound.egress = "direct"`.
 *
 * It takes a string or `URL` (a `Request` is a `TypeError`), `GET` or
 * `POST`, a string, `URLSearchParams` or `Uint8Array` body, any headers, and
 * a `signal`; redirects are never followed. A caller's abort rejects with its
 * own reason; the deadline is the shorter of the caller's and this one's.
 */
export function createOutboundFetch(options: OutboundFetchOptions): typeof fetch {
	return buildOutboundFetch(options, {
		lookup: systemLookup,
		lookups: processLookups,
		transport: nodeTransport,
	});
}

/** Whether `err` is the outbound fetch refusing a destination or an answer, as against the exchange failing. */
export function isOutboundRefusal(err: unknown): boolean {
	return err instanceof OutboundFetchError && err.refusal;
}
