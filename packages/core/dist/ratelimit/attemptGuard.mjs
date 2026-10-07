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
import { auditedError } from "../audit/auditedError.mjs";
import { emitAuditEvent } from "../audit/factory.mjs";
import { checkDeploymentMode } from "../deployment/mode.mjs";
import { auditErrorText, errorEnvelope } from "../errors/envelope.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
import { loggableError } from "../logging/loggableError.mjs";
import { isAttemptSpec, readAttemptCount, } from "./attempts.mjs";
import { createMemoryAttemptCounter } from "./attemptsMemory.mjs";
/** How long a consume is waited for by default before the guard answers `503`. */
export const DEFAULT_ATTEMPT_COUNTER_TIMEOUT_MS = 2_000;
/** The longest id a key carries as it is; a longer one is carried as `h:<sha256 hex>`. */
const MAX_PLAIN_ID_LENGTH = 128;
/** The longest tag: with a hashed id, every key stays well inside a counter's key bound. */
const MAX_TAG_LENGTH = 64;
/** The 503 body of an attempt counter outage. */
export const attemptCounterUnavailableEnvelope = () => errorEnvelope("service_unavailable", "Attempt counter temporarily unavailable");
/** `start`'s answer as a value, however it failed, a synchronous throw included. */
function settle(start) {
    return Promise.resolve()
        .then(start)
        .then((value) => ({ ok: true, value }), (error) => ({ ok: false, error }));
}
/** `work`, or `"elapsed"` when it has not settled within `ms`. No timer is left behind. */
async function within(work, ms) {
    let timer;
    const elapsed = new Promise((resolve) => {
        timer = setTimeout(() => resolve("elapsed"), ms);
    });
    try {
        return await Promise.race([work, elapsed]);
    }
    finally {
        clearTimeout(timer);
    }
}
/** The longest delay `setTimeout` keeps: a longer one fires at once. */
const MAX_TIMER_MS = 2_147_483_647;
const isUsableTimeout = (value) => typeof value === "number" && Number.isInteger(value) && value > 0 && value <= MAX_TIMER_MS;
function checkTag(tag) {
    if (typeof tag !== "string" ||
        tag.length === 0 ||
        tag.length > MAX_TAG_LENGTH ||
        tag.includes(":")) {
        throw new RangeError(`createAttemptGuard: tag must be a non-empty string of at most ${MAX_TAG_LENGTH} characters, without ':'`);
    }
    return tag;
}
function checkSpec(spec, tag) {
    const copy = typeof spec === "object" && spec !== null
        ? {
            limit: spec.limit,
            windowSeconds: spec.windowSeconds,
        }
        : spec;
    if (!isAttemptSpec(copy)) {
        throw new RangeError(`createAttemptGuard: ${tag}'s spec must be { limit, windowSeconds } as positive whole numbers, the window at most a day`);
    }
    return Object.freeze(copy);
}
/**
 * The counter the guard runs on: the shared one, or a per-process one where
 * the deployment mode allows it.
 */
function counterFor(options, tag, spec, logger) {
    const mode = checkDeploymentMode(options.deploymentMode, "createAttemptGuard: deploymentMode");
    const { counter } = options;
    if (counter !== undefined) {
        if (typeof counter.consume !== "function") {
            throw new TypeError("createAttemptGuard: counter must be an AttemptCounter, with consume");
        }
        return counter;
    }
    // A per-process count is the limit times the replicas, and resets on every deploy.
    if (mode === "multi") {
        throw new Error(`createAttemptGuard: core.deployment.mode is "multi" but no shared attemptCounter is wired for "${tag}": a per-process counter would allow ${spec.limit} attempts per ${spec.windowSeconds}s on every replica, reset on every deploy. Wire an attemptCounter, or set core.deployment.mode = "single".`);
    }
    if (mode === "unset") {
        logger.warn({ tag, limit: spec.limit, windowSeconds: spec.windowSeconds }, "attempt_counter_not_shared");
    }
    return createMemoryAttemptCounter({
        logger,
        tag,
        ...(options.now === undefined ? {} : { now: options.now }),
        ...(options.maxEntries === undefined ? {} : { maxEntries: options.maxEntries }),
    });
}
export function createAttemptGuard(options) {
    const tag = checkTag(options.tag);
    const spec = checkSpec(options.spec, tag);
    const logger = options.logger ?? consoleLogger;
    const timeoutMs = options.timeoutMs ?? DEFAULT_ATTEMPT_COUNTER_TIMEOUT_MS;
    if (!isUsableTimeout(timeoutMs)) {
        throw new RangeError(`createAttemptGuard: timeoutMs must be a positive whole number of at most ${MAX_TIMER_MS}`);
    }
    const refused = errorEnvelope(options.refused?.error ?? "rate_limited", options.refused?.description ?? "Rate limit exceeded");
    const now = options.now ?? Date.now;
    const { auditSink } = options;
    const counter = counterFor(options, tag, spec, logger);
    /** `<tag>:<id>`, the id hashed when it is long. */
    const keyFor = (id) => `${tag}:${id.length > MAX_PLAIN_ID_LENGTH || id.startsWith("h:")
        ? `h:${createHash("sha256").update(id).digest("hex")}`
        : id}`;
    /** The count, or why there is none. */
    const consume = async (key) => {
        const answered = await within(settle(() => counter.consume(key, spec)), timeoutMs);
        if (answered === "elapsed")
            return { failure: "timed_out" };
        if (!answered.ok)
            return { failure: "threw", error: answered.error };
        return readAttemptCount(answered.value, spec, now()) ?? { failure: "malformed" };
    };
    const reportOutage = (req, { failure, error }) => {
        const ip = req.ip ?? "unknown";
        const threw = failure === "threw";
        const projected = threw ? loggableError(error) : undefined;
        logger.error({
            tag,
            failure,
            ip: auditErrorText(ip),
            ...(projected === undefined ? {} : { error: projected.detail ?? projected.name }),
        }, "attempt_counter_unavailable");
        emitAuditEvent(auditSink, {
            timestamp: new Date(),
            type: "rate_limit.unavailable",
            ip,
            userAgent: req.get("user-agent"),
            details: { tag, failure, ...(threw ? { cause: auditedError(error) } : {}) },
        });
    };
    const attempt = async (req, res, id) => {
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
    const perIp = ({ onRefused } = {}) => async (req, res, next) => {
        const verdict = await attempt(req, res, `ip:${req.ip ?? "unknown"}`);
        if (verdict.verdict === "allowed") {
            next();
            return;
        }
        if (verdict.verdict !== "refused" || onRefused === undefined)
            return;
        const { count } = verdict;
        // A hook's throw or rejection is reported here; it never reaches the response or the process.
        void Promise.resolve()
            .then(() => onRefused(req, count))
            .catch((error) => {
            const projected = loggableError(error);
            logger.error({ tag, error: projected.detail ?? projected.name }, "attempt_refused_hook_failed");
        });
    };
    return { attempt, perIp };
}
