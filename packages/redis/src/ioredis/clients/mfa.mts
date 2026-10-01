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
 * The MFA stores' clients over one ioredis connection each, with the durability report both
 * give the boot check. A reservation reply the script does not document throws: an outage,
 * never a verdict.
 */

import type { Redis } from "ioredis";
import type { MfaFactorStoreClient, MfaTransactionStoreClient } from "../../clients.mjs";
import { fgNumber, hashFields } from "../codec.mjs";
import { runScript } from "../commands.mjs";
import { redisDurability } from "../durability.mjs";
import { COMPARE_AND_DELETE } from "../scripts/lock.mjs";
import {
	MFA_FACTOR_UPDATE,
	MFA_FIRST_BINDING_NOTE,
	MFA_FIRST_BINDING_READ,
	MFA_RECOVERY_SET_FLOOR_RAISE,
	MFA_SUBJECT_EXEMPT,
	MFA_SUBJECT_LEASE_ACQUIRE,
	MFA_SUBJECT_RECOVERY_APPLY,
	MFA_SUBJECT_RECOVERY_AUTHORIZE,
	MFA_SUBJECT_RESERVE,
	MFA_SUBJECT_SETTLE,
	MFA_TX_CONSUME,
	MFA_TX_CREATE,
	MFA_TX_RESERVE_ATTEMPT,
	MFA_TX_TAKE_CHALLENGE,
	MFA_TX_UPDATE,
} from "../scripts/mfa.mjs";

/**
 * The `MfaFactorStore`'s client over one ioredis connection. Also part of
 * {@link makeIoredisClients}; exported alone so a deployment can keep enrolled factors on a
 * dedicated database or instance, as the MFA ADR's durability requirements prefer.
 */
export function makeIoredisMfaFactorStoreClient(io: Redis): MfaFactorStoreClient {
	return {
		async list(key) {
			return await io.hgetall(key);
		},
		async create(key, field, value) {
			return (await io.hsetnx(key, field, value)) === 1;
		},
		async update(key, field, input) {
			const reply = await runScript(
				io,
				MFA_FACTOR_UPDATE,
				[key],
				[field, input.expectedVersion, input.nextVersion, input.mutable],
			);
			return typeof reply === "string" ? reply : null;
		},
		async remove(key, field) {
			await io.hdel(key, field);
		},
		async removeAll(key) {
			await io.del(key);
		},
		durability: () => redisDurability(io),
	};
}

const HOLDS: ReadonlySet<unknown> = new Set(["backoff", "weekly", "hard"]);

/** The server's clock as a script answers it: decimal text of whole milliseconds; `undefined` for anything else. */
const serverMs = (text: unknown): number | undefined =>
	typeof text === "string" && /^(0|[1-9][0-9]*)$/.test(text) && Number.isSafeInteger(Number(text))
		? Number(text)
		: undefined;

/** The apply script's rebind argument: the time, `none` when no guessable record remains, empty for a reset. */
const rebindArgument = (since: number | null | undefined): string =>
	since === null ? "none" : since === undefined ? "" : String(since);

/**
 * The `MfaTransactionStore`'s client over one ioredis connection. Also part of
 * {@link makeIoredisClients}; exported alone so a deployment can give it a dedicated database
 * or instance.
 */
export function makeIoredisMfaTransactionStoreClient(io: Redis): MfaTransactionStoreClient {
	return {
		async create(key, fields, deadlineMs) {
			const reply = await runScript(
				io,
				MFA_TX_CREATE,
				[key],
				[fgNumber(deadlineMs), ...Object.entries(fields).flat()],
			);
			return reply === 1;
		},
		async read(key) {
			return await io.hgetall(key);
		},
		async update(key, input) {
			const set = Object.entries(input.set);
			const reply = await runScript(
				io,
				MFA_TX_UPDATE,
				[key],
				[
					input.expectedVersion,
					input.incarnation,
					String(set.length),
					...set.flat(),
					...input.clear,
				],
			);
			return Array.isArray(reply) ? hashFields(reply) : null;
		},
		async reserveAttempt(key, max, nowMs) {
			const reply = await runScript(
				io,
				MFA_TX_RESERVE_ATTEMPT,
				[key],
				[String(max), String(nowMs)],
			);
			const [ok, attempts] = Array.isArray(reply) ? reply : [0, 0];
			return { ok: ok === 1, attempts: Number(attempts) };
		},
		async takeChallenge(key, expectedVersion, nowMs) {
			const reply = await runScript(
				io,
				MFA_TX_TAKE_CHALLENGE,
				[key],
				[expectedVersion, String(nowMs)],
			);
			return typeof reply === "string" ? reply : null;
		},
		async consume(key, expectedVersion) {
			const reply = await runScript(io, MFA_TX_CONSUME, [key], [expectedVersion]);
			return Array.isArray(reply) ? hashFields(reply) : null;
		},
		async reserveSubjectAttempt(keys, input) {
			const { policy } = input;
			const reply = await runScript(
				io,
				MFA_SUBJECT_RESERVE,
				[keys.lock, keys.week],
				[
					String(input.nowMs),
					String(policy.threshold),
					String(policy.baseSeconds),
					String(policy.maxSeconds),
					String(policy.memorySeconds),
					String(policy.weeklyBudget),
					String(policy.hardLimit),
					input.reservation,
				],
			);
			if (Array.isArray(reply) && reply[0] === "ok") return { ok: true };
			const [outcome, hold, retry, first] = Array.isArray(reply) ? reply : [];
			if (outcome === "held" && HOLDS.has(hold) && (first === "1" || first === "0")) {
				return {
					ok: false,
					hold: hold as "backoff" | "weekly" | "hard",
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
			await runScript(
				io,
				MFA_SUBJECT_EXEMPT,
				[keys.lock, keys.week],
				[String(input.nowMs), String(input.policy.hardLimit)],
			);
		},
		async requireEmailProof(key) {
			await io.set(key, "1");
		},
		async emailProofRequired(key) {
			return (await io.exists(key)) === 1;
		},
		async consumeEmailProof(key) {
			return (await io.del(key)) === 1;
		},
		async recordSessionEmailProof(key, value, ttlMs) {
			await io.set(key, value, "PX", ttlMs);
		},
		async sessionEmailProof(key) {
			return await io.get(key);
		},
		async noteFirstBinding(key, input) {
			const reply = await runScript(
				io,
				MFA_FIRST_BINDING_NOTE,
				[key],
				[String(input.atMs), String(input.untilMs), String(input.skewMs), String(input.longestMs)],
			);
			const [noted, now] = Array.isArray(reply) ? reply : [];
			const serverNowMs = serverMs(now);
			if (noted === 1 && serverNowMs !== undefined) return { noted: true };
			if (noted === 0 && serverNowMs !== undefined) return { noted: false, serverNowMs };
			throw new Error(
				"MfaTransactionStore: the first-binding note script answered nothing it knows",
			);
		},
		async firstBindingMark(key) {
			const reply = await runScript(io, MFA_FIRST_BINDING_READ, [key], []);
			const [now, value] = Array.isArray(reply) ? reply : [];
			const serverNowMs = serverMs(now);
			if (serverNowMs === undefined || (value !== null && typeof value !== "string")) {
				throw new Error(
					"MfaTransactionStore: the first-binding read script answered nothing it knows",
				);
			}
			return { value, serverNowMs };
		},
		async subjectGeneration(keys) {
			return await io.hget(keys.recovery, "g");
		},
		async acquireSubjectLease(keys, input) {
			const reply = await runScript(
				io,
				MFA_SUBJECT_LEASE_ACQUIRE,
				[keys.lease, keys.recovery],
				[input.token, String(input.ttlMs), String(input.generation)],
			);
			const [outcome, pttl] = Array.isArray(reply) ? reply : [];
			if (outcome === "acquired" || outcome === "stale") return { outcome };
			// A lease at its last millisecond answers 0: still busy, for at least one more. One with
			// no deadline (PTTL -1) is none this store wrote: no verdict.
			if (outcome === "busy" && typeof pttl === "number" && pttl >= 0) {
				return { outcome, retryAfterMs: Math.max(pttl, 1) };
			}
			throw new Error("MfaTransactionStore: the lease script answered nothing it knows");
		},
		async releaseSubjectLease(keys, token) {
			return (await runScript(io, COMPARE_AND_DELETE, [keys.lease], [token])) === 1;
		},
		async recoverySetFloor(keys) {
			return await io.hget(keys.recovery, "floor");
		},
		async raiseRecoverySetFloor(keys, input) {
			const reply = await runScript(
				io,
				MFA_RECOVERY_SET_FLOOR_RAISE,
				[keys.recovery, keys.lease],
				[String(input.setGeneration), input.leaseToken],
			);
			const [raised, floor] = Array.isArray(reply) ? reply : [];
			if (raised === 0) return { raised: false };
			if (raised === 1 && typeof floor === "string") return { raised: true, floor };
			throw new Error("MfaTransactionStore: the floor script answered nothing it knows");
		},
		async authorizeSubjectRecovery(keys, input) {
			const reply = await runScript(
				io,
				MFA_SUBJECT_RECOVERY_AUTHORIZE,
				[keys.recovery],
				[input.field, input.recoveryId, String(input.expiresAtMs), String(input.maxAheadMs)],
			);
			const [authorized, now] = Array.isArray(reply) ? reply : [];
			const serverNowMs = serverMs(now);
			if (authorized === 1 && serverNowMs !== undefined) return { authorized: true };
			if (authorized === 0 && serverNowMs !== undefined) return { authorized: false, serverNowMs };
			throw new Error("MfaTransactionStore: the authorize script answered nothing it knows");
		},
		async applySubjectRecovery(keys, input) {
			const reply = await runScript(
				io,
				MFA_SUBJECT_RECOVERY_APPLY,
				[keys.lock, keys.week, keys.recovery, keys.lease],
				[
					input.operation,
					input.field,
					String(input.nowMs),
					input.leaseToken,
					input.sessionsBoundaryMs === undefined ? "" : String(input.sessionsBoundaryMs),
					rebindArgument(input.guessableBoundSinceMs),
					String(input.clockSkewMs),
				],
			);
			if (!Array.isArray(reply) || !reply.every((part) => typeof part === "string")) {
				throw new Error("MfaTransactionStore: the apply script answered nothing it knows");
			}
			return reply;
		},
		durability: () => redisDurability(io),
	};
}
