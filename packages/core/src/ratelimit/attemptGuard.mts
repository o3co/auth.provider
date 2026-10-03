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
 * The guard a verifier's own attempt limit runs through: one attempt counted
 * per request against the spec its owning module hands in, never against a
 * rate limiter's budgets. It owns three things its callers must not decide:
 *
 * - the per-process fallback when no shared counter is wired, as the
 *   deployment mode allows it: refused under `multi`, warned when unset,
 *   silent under `single`;
 * - failing closed: a counter that throws, does not answer within
 *   `timeoutMs`, or answers something `readAttemptCount` refuses is an outage,
 *   answered `503` whatever the counter declares, logged and audited;
 * - what a response says of the count: on a refusal `Retry-After` alone,
 *   with `Cache-Control: no-store` on every answer it writes, and never
 *   `RateLimit-*`, which would tell whoever guesses a secret how many guesses
 *   are left and when more come.
 *
 * A key's id longer than {@link MAX_PLAIN_ID_LENGTH}, or one that starts with
 * `h:`, is handed to the counter as its SHA-256, so neither a long key nor a
 * long raw value reaches a store, and no id is taken for a hashed one.
 *
 * Use one key kind per guard (per IP, or per user), with a guard of its own
 * for each: under one per-process counter, cheap keys of one kind would push
 * out the scarce windows of the other.
 */

import { createHash } from "node:crypto";
import type { Request, RequestHandler, Response } from "express";
import { auditedError } from "../audit/auditedError.mjs";
import { emitAuditEvent } from "../audit/factory.mjs";
import type { AuditSink } from "../audit/types.mjs";
import { checkDeploymentMode } from "../deployment/mode.mjs";
import type { DeploymentMode } from "../deployment/types.mjs";
import { auditErrorText, type ErrorEnvelope, errorEnvelope } from "../errors/envelope.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
import type { Logger } from "../logging/Logger.mjs";
import { loggableError } from "../logging/loggableError.mjs";
import {
	type AttemptCount,
	type AttemptCounter,
	type AttemptSpec,
	isAttemptSpec,
	readAttemptCount,
} from "./attempts.mjs";
import { createMemoryAttemptCounter } from "./attemptsMemory.mjs";

/** How long a consume is waited for by default before the guard answers `503`. */
export const DEFAULT_ATTEMPT_COUNTER_TIMEOUT_MS = 2_000;

/** The longest id a key carries as it is; a longer one is carried as `h:<sha256 hex>`. */
const MAX_PLAIN_ID_LENGTH = 128;

/** The longest tag: with a hashed id, every key stays well inside a counter's key bound. */
const MAX_TAG_LENGTH = 64;

export interface AttemptGuardOptions {
	/** The `attemptCounter` slot's value. Absent: a per-process counter, where the deployment mode allows one. */
	readonly counter?: AttemptCounter;
	/** The `deploymentMode` slot's value. */
	readonly deploymentMode: DeploymentMode;
	/** The key prefix (`<tag>:<id>`) and the `tag` on the guard's log and audit emissions. No `:`. */
	readonly tag: string;
	/** The owning module's limit, read once here: every key under `tag` is counted against it. */
	readonly spec: AttemptSpec;
	/** Defaults to `consoleLogger`. */
	readonly logger?: Logger;
	/** When present, an outage is also audited as `rate_limit.unavailable`. */
	readonly auditSink?: AuditSink;
	/** How long a consume is waited for. Default {@link DEFAULT_ATTEMPT_COUNTER_TIMEOUT_MS}. */
	readonly timeoutMs?: number;
	/** The 429's error code and description. Default `rate_limited`, "Rate limit exceeded". */
	readonly refused?: { readonly error: string; readonly description: string };
	/** Epoch milliseconds, for reading a count and for the per-process counter. Default `Date.now`. */
	readonly now?: () => number;
	/** The per-process counter's `maxEntries`; a shared counter is sized by its own backend. */
	readonly maxEntries?: number;
}

export interface AttemptPerIpOptions {
	/**
	 * Called after a refusal is answered, so the owning module can audit it.
	 * A throw or a rejection is logged `attempt_refused_hook_failed` and changes nothing.
	 */
	readonly onRefused?: (req: Request, count: AttemptCount) => unknown;
}

/** What the guard answered an attempt with. Only on `allowed` does the caller go on; the others are already answered. */
export type AttemptVerdict =
	| { readonly verdict: "allowed"; readonly count: AttemptCount }
	| { readonly verdict: "refused"; readonly count: AttemptCount }
	| { readonly verdict: "unavailable" };

export interface AttemptGuard {
	/** Counts one attempt under `<tag>:<id>`, and answers the request itself unless it is allowed. */
	attempt(req: Request, res: Response, id: string): Promise<AttemptVerdict>;
	/** Middleware counting one attempt per request under `<tag>:ip:<req.ip>`. */
	perIp(options?: AttemptPerIpOptions): RequestHandler;
}

/** Why a counter had no usable answer. */
export type AttemptCounterFailure = "threw" | "timed_out" | "malformed";

/** The 503 body of an attempt counter outage. */
export const attemptCounterUnavailableEnvelope = (): ErrorEnvelope =>
	errorEnvelope("service_unavailable", "Attempt counter temporarily unavailable");

/** A consume with no usable answer: why, and what it threw. */
interface Outage {
	readonly failure: AttemptCounterFailure;
	readonly error?: unknown;
}

type Settled<T> =
	| { readonly ok: true; readonly value: T }
	| { readonly ok: false; readonly error: unknown };

/** `start`'s answer as a value, however it failed, a synchronous throw included. */
function settle<T>(start: () => T | Promise<T>): Promise<Settled<T>> {
	return Promise.resolve()
		.then(start)
		.then(
			(value) => ({ ok: true as const, value }),
			(error: unknown) => ({ ok: false as const, error }),
		);
}

/** `work`, or `"elapsed"` when it has not settled within `ms`. No timer is left behind. */
async function within<T>(work: Promise<T>, ms: number): Promise<T | "elapsed"> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	const elapsed = new Promise<"elapsed">((resolve) => {
		timer = setTimeout(() => resolve("elapsed"), ms);
	});
	try {
		return await Promise.race([work, elapsed]);
	} finally {
		clearTimeout(timer);
	}
}

/** The longest delay `setTimeout` keeps: a longer one fires at once. */
const MAX_TIMER_MS = 2_147_483_647;

const isUsableTimeout = (value: unknown): value is number =>
	typeof value === "number" && Number.isInteger(value) && value > 0 && value <= MAX_TIMER_MS;

function checkTag(tag: unknown): string {
	if (
		typeof tag !== "string" ||
		tag.length === 0 ||
		tag.length > MAX_TAG_LENGTH ||
		tag.includes(":")
	) {
		throw new RangeError(
			`createAttemptGuard: tag must be a non-empty string of at most ${MAX_TAG_LENGTH} characters, without ':'`,
		);
	}
	return tag;
}

function checkSpec(spec: unknown, tag: string): AttemptSpec {
	const copy =
		typeof spec === "object" && spec !== null
			? {
					limit: (spec as { limit?: unknown }).limit,
					windowSeconds: (spec as { windowSeconds?: unknown }).windowSeconds,
				}
			: spec;
	if (!isAttemptSpec(copy)) {
		throw new RangeError(
			`createAttemptGuard: ${tag}'s spec must be { limit, windowSeconds } as positive whole numbers, the window at most a year`,
		);
	}
	return Object.freeze(copy);
}

/**
 * The counter the guard runs on: the shared one, or a per-process one where
 * the deployment mode allows it.
 */
function counterFor(
	options: AttemptGuardOptions,
	tag: string,
	spec: AttemptSpec,
	logger: Logger,
): AttemptCounter {
	const mode = checkDeploymentMode(options.deploymentMode, "createAttemptGuard: deploymentMode");
	const { counter } = options;
	if (counter !== undefined) {
		if (typeof (counter as { consume?: unknown }).consume !== "function") {
			throw new TypeError("createAttemptGuard: counter must be an AttemptCounter, with consume");
		}
		return counter;
	}
	// A per-process count is the limit times the replicas, and resets on every deploy.
	if (mode === "multi") {
		throw new Error(
			`createAttemptGuard: core.deployment.mode is "multi" but no shared attemptCounter is wired for "${tag}": a per-process counter would allow ${spec.limit} attempts per ${spec.windowSeconds}s on every replica, reset on every deploy. Wire an attemptCounter, or set core.deployment.mode = "single".`,
		);
	}
	if (mode === "unset") {
		logger.warn(
			{ tag, limit: spec.limit, windowSeconds: spec.windowSeconds },
			"attempt_counter_not_shared",
		);
	}
	return createMemoryAttemptCounter({
		logger,
		tag,
		...(options.now === undefined ? {} : { now: options.now }),
		...(options.maxEntries === undefined ? {} : { maxEntries: options.maxEntries }),
	});
}

export function createAttemptGuard(options: AttemptGuardOptions): AttemptGuard {
	const tag = checkTag(options.tag);
	const spec = checkSpec(options.spec, tag);
	const logger = options.logger ?? consoleLogger;
	const timeoutMs = options.timeoutMs ?? DEFAULT_ATTEMPT_COUNTER_TIMEOUT_MS;
	if (!isUsableTimeout(timeoutMs)) {
		throw new RangeError(
			`createAttemptGuard: timeoutMs must be a positive whole number of at most ${MAX_TIMER_MS}`,
		);
	}
	const refused = errorEnvelope(
		options.refused?.error ?? "rate_limited",
		options.refused?.description ?? "Rate limit exceeded",
	);
	const now = options.now ?? Date.now;
	const { auditSink } = options;
	const counter = counterFor(options, tag, spec, logger);

	/** `<tag>:<id>`, the id hashed when it is long. */
	const keyFor = (id: string): string =>
		`${tag}:${
			id.length > MAX_PLAIN_ID_LENGTH || id.startsWith("h:")
				? `h:${createHash("sha256").update(id).digest("hex")}`
				: id
		}`;

	/** The count, or why there is none. */
	const consume = async (key: string): Promise<AttemptCount | Outage> => {
		const answered = await within(
			settle(() => counter.consume(key, spec)),
			timeoutMs,
		);
		if (answered === "elapsed") return { failure: "timed_out" };
		if (!answered.ok) return { failure: "threw", error: answered.error };
		return readAttemptCount(answered.value, spec, now()) ?? { failure: "malformed" };
	};

	const reportOutage = (req: Request, { failure, error }: Outage): void => {
		const ip = req.ip ?? "unknown";
		const threw = failure === "threw";
		const projected = threw ? loggableError(error) : undefined;
		logger.error(
			{
				tag,
				failure,
				ip: auditErrorText(ip),
				...(projected === undefined ? {} : { error: projected.detail ?? projected.name }),
			},
			"attempt_counter_unavailable",
		);
		emitAuditEvent(auditSink, {
			timestamp: new Date(),
			type: "rate_limit.unavailable",
			ip,
			userAgent: req.get("user-agent"),
			details: { tag, failure, ...(threw ? { cause: auditedError(error) } : {}) },
		});
	};

	const attempt = async (req: Request, res: Response, id: string): Promise<AttemptVerdict> => {
		const outcome = await consume(keyFor(id));
		if ("failure" in outcome) {
			reportOutage(req, outcome);
			res.status(503).set("Cache-Control", "no-store").json(attemptCounterUnavailableEnvelope());
			return { verdict: "unavailable" };
		}
		if (!outcome.allowed) {
			const retryAfter = Math.max(0, Math.ceil((outcome.resetAt.getTime() - now()) / 1000));
			res
				.status(429)
				.set({ "Cache-Control": "no-store", "Retry-After": String(retryAfter) })
				.json(refused);
			return { verdict: "refused", count: outcome };
		}
		return { verdict: "allowed", count: outcome };
	};

	const perIp =
		({ onRefused }: AttemptPerIpOptions = {}): RequestHandler =>
		async (req, res, next) => {
			const verdict = await attempt(req, res, `ip:${req.ip ?? "unknown"}`);
			if (verdict.verdict === "allowed") {
				next();
				return;
			}
			if (verdict.verdict !== "refused" || onRefused === undefined) return;
			const { count } = verdict;
			// A hook's throw or rejection is reported here; it never reaches the response or the process.
			void Promise.resolve()
				.then(() => onRefused(req, count))
				.catch((error: unknown) => {
					const projected = loggableError(error);
					logger.error(
						{ tag, error: projected.detail ?? projected.name },
						"attempt_refused_hook_failed",
					);
				});
		};

	return { attempt, perIp };
}
