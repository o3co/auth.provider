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
import { fgNumber, hashFields } from "../codec.mjs";
import { runScript } from "../commands.mjs";
import { redisDurability } from "../durability.mjs";
import { MFA_BINDING_INDEX, MFA_BINDING_UNINDEX, MFA_EMAIL_PROOF_CONSUME, MFA_FACTOR_CREATE_IF, MFA_FACTOR_LIST_VERSIONED, MFA_FACTOR_REMOVE_ALL, MFA_FACTOR_REMOVE_IF, MFA_FACTOR_UPDATE, MFA_FIRST_BINDING_NOTE, MFA_FIRST_BINDING_READ, MFA_RECOVERY_SET_FLOOR_RAISE, MFA_SUBJECT_EXEMPT, MFA_SUBJECT_LEASE_ACQUIRE, MFA_SUBJECT_LEASE_RELEASE, MFA_SUBJECT_RECOVERY_APPLY, MFA_SUBJECT_RECOVERY_AUTHORIZE, MFA_SUBJECT_RESERVE, MFA_SUBJECT_SETTLE, MFA_TX_CONSUME, MFA_TX_CREATE, MFA_TX_EVICT, MFA_TX_RESERVE_ATTEMPT, MFA_TX_TAKE_CHALLENGE, MFA_TX_UPDATE, } from "../scripts/mfa.mjs";
/**
 * A membership script's reply as one of `outcomes`; anything else throws, an outage, never an
 * outcome. The message names the operation in fixed words and quotes nothing it read.
 */
function outcomeOf(reply, outcomes, operation) {
    if (outcomes.includes(reply))
        return reply;
    throw new Error(`mfaFactorStoreClient.${operation}: the script answered a reply it does not document`);
}
/**
 * The `MfaFactorStore`'s client over one ioredis connection. Also part of
 * {@link makeIoredisClients}; exported alone so a deployment can keep enrolled factors on a
 * dedicated database or instance, as the MFA ADR's durability requirements prefer.
 */
export function makeIoredisMfaFactorStoreClient(io, options = {}) {
    return {
        async list(key) {
            return await io.hgetall(key);
        },
        async listVersioned(key, mint) {
            const reply = await runScript(io, MFA_FACTOR_LIST_VERSIONED, [key], [mint]);
            if (!Array.isArray(reply) || reply.length % 2 !== 0) {
                throw new Error("mfaFactorStoreClient.listVersioned: the script answered a reply it does not document");
            }
            // Each field an own property, `__proto__` included, as `HGETALL`'s
            // reply gives `list`: a field the adapter cannot read is refused there,
            // never dropped here.
            const pairs = [];
            for (let i = 0; i < reply.length; i += 2) {
                pairs.push([String(reply[i]), String(reply[i + 1])]);
            }
            return Object.fromEntries(pairs);
        },
        async createIf(key, field, value, input) {
            const reply = await runScript(io, MFA_FACTOR_CREATE_IF, [key, input.replayKey], [
                input.next,
                String(input.deadlineMs),
                String(input.clockSkewMs),
                input.expected ?? "",
                field,
                value,
            ]);
            return outcomeOf(reply, ["created", "conflict", "late"], "createIf");
        },
        async removeIf(key, field, input) {
            const reply = await runScript(io, MFA_FACTOR_REMOVE_IF, [key, input.replayKey], [
                input.next,
                String(input.deadlineMs),
                String(input.clockSkewMs),
                String(input.tombstoneMs),
                input.expected,
                field,
            ]);
            return outcomeOf(reply, ["removed", "missing", "conflict", "late"], "removeIf");
        },
        async update(key, field, input) {
            const reply = await runScript(io, MFA_FACTOR_UPDATE, [key], [field, input.expectedVersion, input.nextVersion, input.mutable]);
            return typeof reply === "string" ? reply : null;
        },
        async removeAll(key, input) {
            const reply = await runScript(io, MFA_FACTOR_REMOVE_ALL, [key, input.replayKey], [
                input.next,
                String(input.deadlineMs),
                String(input.clockSkewMs),
                String(input.tombstoneMs),
            ]);
            return outcomeOf(reply, ["removed", "late"], "removeAll");
        },
        durability: () => redisDurability(io, options),
    };
}
const HOLDS = new Set(["backoff", "weekly", "hard"]);
/** The server's clock as a script answers it: decimal text of whole milliseconds; `undefined` for anything else. */
const serverMs = (text) => typeof text === "string" && /^(0|[1-9][0-9]*)$/.test(text) && Number.isSafeInteger(Number(text))
    ? Number(text)
    : undefined;
/** The apply script's rebind argument: the time, `none` when no guessable record remains, empty for a reset. */
const rebindArgument = (since) => since === null ? "none" : since === undefined ? "" : String(since);
/**
 * The `MfaTransactionStore`'s client over one ioredis connection. Also part of
 * {@link makeIoredisClients}; exported alone so a deployment can give it a dedicated database
 * or instance.
 */
export function makeIoredisMfaTransactionStoreClient(io, options = {}) {
    return {
        async create(key, fields, deadlineMs) {
            const reply = await runScript(io, MFA_TX_CREATE, [key], [fgNumber(deadlineMs), ...Object.entries(fields).flat()]);
            return reply === 1;
        },
        async read(key) {
            return await io.hgetall(key);
        },
        async update(key, input) {
            const set = Object.entries(input.set);
            const reply = await runScript(io, MFA_TX_UPDATE, [key], [
                input.expectedVersion,
                input.incarnation,
                String(set.length),
                ...set.flat(),
                ...input.clear,
            ]);
            return Array.isArray(reply) ? hashFields(reply) : null;
        },
        async reserveAttempt(key, max, nowMs) {
            const reply = await runScript(io, MFA_TX_RESERVE_ATTEMPT, [key], [String(max), String(nowMs)]);
            const [ok, attempts, index, incarnation] = Array.isArray(reply) ? reply : [0, 0];
            const answer = { ok: ok === 1, attempts: Number(attempts) };
            return typeof index === "string" && typeof incarnation === "string"
                ? { ...answer, removed: { index, incarnation } }
                : answer;
        },
        async takeChallenge(key, expectedVersion, nowMs) {
            const reply = await runScript(io, MFA_TX_TAKE_CHALLENGE, [key], [expectedVersion, String(nowMs)]);
            return typeof reply === "string" ? reply : null;
        },
        async consume(key, expectedVersion) {
            const reply = await runScript(io, MFA_TX_CONSUME, [key], [expectedVersion]);
            return Array.isArray(reply) ? hashFields(reply) : null;
        },
        async indexTransaction(key, member, expiresAtMs, max) {
            const reply = await runScript(io, MFA_BINDING_INDEX, [key], [member, String(expiresAtMs), String(max)]);
            return Array.isArray(reply)
                ? reply.filter((removed) => typeof removed === "string")
                : [];
        },
        async unindexTransaction(key, member) {
            await runScript(io, MFA_BINDING_UNINDEX, [key], [member]);
        },
        async evictTransaction(key, incarnation) {
            return (await runScript(io, MFA_TX_EVICT, [key], [incarnation])) === 1;
        },
        async reserveSubjectAttempt(keys, input) {
            const { policy } = input;
            const reply = await runScript(io, MFA_SUBJECT_RESERVE, [keys.lock, keys.week], [
                String(input.nowMs),
                String(policy.threshold),
                String(policy.baseSeconds),
                String(policy.maxSeconds),
                String(policy.memorySeconds),
                String(policy.weeklyBudget),
                String(policy.hardLimit),
                input.reservation,
            ]);
            if (Array.isArray(reply) && reply[0] === "ok")
                return { ok: true };
            const [outcome, hold, retry, first] = Array.isArray(reply) ? reply : [];
            if (outcome === "held" && HOLDS.has(hold) && (first === "1" || first === "0")) {
                return {
                    ok: false,
                    hold: hold,
                    retryAfterMs: retry === "" ? null : Number(retry),
                    first: first === "1",
                };
            }
            // A reply this release does not know is not a verdict: refuse the
            // attempt as an outage rather than let it through or hold it.
            throw new Error("MfaTransactionStore: the reservation script answered nothing it knows");
        },
        async settleSubjectAttempt(keys, reservation, outcome) {
            await runScript(io, MFA_SUBJECT_SETTLE, [keys.lock, keys.week], [reservation, outcome]);
        },
        async noteExemptSuccess(keys, input) {
            await runScript(io, MFA_SUBJECT_EXEMPT, [keys.lock, keys.week], [String(input.nowMs), String(input.policy.hardLimit)]);
        },
        async requireEmailProof(key) {
            await io.set(key, "1");
        },
        async emailProofRequired(key) {
            return (await io.exists(key)) === 1;
        },
        async consumeEmailProof(keys, leaseToken) {
            const reply = await runScript(io, MFA_EMAIL_PROOF_CONSUME, [keys.proof, keys.lease], [leaseToken]);
            const [held, removed] = Array.isArray(reply) ? reply : [];
            if (held === 0)
                return { held: false };
            if (held === 1 && (removed === 0 || removed === 1))
                return { held: true, removed: removed === 1 };
            throw new Error("MfaTransactionStore: the email-proof consume script answered nothing it knows");
        },
        async recordSessionEmailProof(key, value, ttlMs) {
            await io.set(key, value, "PX", ttlMs);
        },
        async sessionEmailProof(key) {
            return await io.get(key);
        },
        async noteFirstBinding(key, input) {
            const reply = await runScript(io, MFA_FIRST_BINDING_NOTE, [key], [String(input.atMs), String(input.untilMs), String(input.skewMs), String(input.longestMs)]);
            const [noted, now, kind, at] = Array.isArray(reply) ? reply : [];
            const serverNowMs = serverMs(now);
            if (noted === 1 && serverNowMs !== undefined) {
                if (kind === "none")
                    return { noted: true, earlier: null };
                if (kind === "unreadable")
                    return { noted: true, earlier: "unreadable" };
                const atMs = serverMs(at);
                if (kind === "mark" && atMs !== undefined)
                    return { noted: true, earlier: { atMs } };
            }
            if (noted === 0 && serverNowMs !== undefined)
                return { noted: false, serverNowMs };
            throw new Error("MfaTransactionStore: the first-binding note script answered nothing it knows");
        },
        async firstBindingMark(key) {
            const reply = await runScript(io, MFA_FIRST_BINDING_READ, [key], []);
            const [now, value] = Array.isArray(reply) ? reply : [];
            const serverNowMs = serverMs(now);
            if (serverNowMs === undefined || (value !== null && typeof value !== "string")) {
                throw new Error("MfaTransactionStore: the first-binding read script answered nothing it knows");
            }
            return { value, serverNowMs };
        },
        async subjectGeneration(keys) {
            return await io.hget(keys.recovery, "g");
        },
        async acquireSubjectLease(keys, input) {
            const reply = await runScript(io, MFA_SUBJECT_LEASE_ACQUIRE, [keys.lease, keys.recovery], [input.token, String(input.ttlMs), String(input.generation)]);
            const [outcome, pttl] = Array.isArray(reply) ? reply : [];
            if (outcome === "acquired" || outcome === "stale")
                return { outcome };
            // A lease at its last millisecond answers 0: still busy, for at least one more. One with
            // no deadline (PTTL -1) is none this store wrote: no verdict.
            if (outcome === "busy" && typeof pttl === "number" && pttl >= 0) {
                return { outcome, retryAfterMs: Math.max(pttl, 1) };
            }
            throw new Error("MfaTransactionStore: the lease script answered nothing it knows");
        },
        async releaseSubjectLease(keys, token) {
            return (await runScript(io, MFA_SUBJECT_LEASE_RELEASE, [keys.lease], [token])) === 1;
        },
        async recoverySetFloor(keys) {
            return await io.hget(keys.recovery, "floor");
        },
        async raiseRecoverySetFloor(keys, input) {
            const reply = await runScript(io, MFA_RECOVERY_SET_FLOOR_RAISE, [keys.recovery, keys.lease], [String(input.setGeneration), input.leaseToken]);
            const [raised, floor] = Array.isArray(reply) ? reply : [];
            if (raised === 0)
                return { raised: false };
            if (raised === 1 && typeof floor === "string")
                return { raised: true, floor };
            throw new Error("MfaTransactionStore: the floor script answered nothing it knows");
        },
        async authorizeSubjectRecovery(keys, input) {
            const reply = await runScript(io, MFA_SUBJECT_RECOVERY_AUTHORIZE, [keys.recovery], [input.field, input.recoveryId, String(input.expiresAtMs), String(input.maxAheadMs)]);
            const [authorized, now] = Array.isArray(reply) ? reply : [];
            const serverNowMs = serverMs(now);
            if (authorized === 1 && serverNowMs !== undefined)
                return { authorized: true };
            if (authorized === 0 && serverNowMs !== undefined)
                return { authorized: false, serverNowMs };
            throw new Error("MfaTransactionStore: the authorize script answered nothing it knows");
        },
        async applySubjectRecovery(keys, input) {
            const reply = await runScript(io, MFA_SUBJECT_RECOVERY_APPLY, [keys.lock, keys.week, keys.recovery, keys.lease], [
                input.operation,
                input.field,
                String(input.nowMs),
                input.leaseToken,
                input.sessionsBoundaryMs === undefined ? "" : String(input.sessionsBoundaryMs),
                rebindArgument(input.guessableBoundSinceMs),
                String(input.clockSkewMs),
            ]);
            if (!Array.isArray(reply) || !reply.every((part) => typeof part === "string")) {
                throw new Error("MfaTransactionStore: the apply script answered nothing it knows");
            }
            return reply;
        },
        durability: () => redisDurability(io, options),
    };
}
