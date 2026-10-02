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
 * Redis {@link MfaFactorStore}: enrolled second factors, one hash per subject.
 *
 * ```text
 * <keyPrefix>{<subject>}   HASH   field <factor id> → the record
 *                                 field ~g          → the set's generation
 * ```
 *
 * `<subject>` and `<factor id>` are base64url of their JSON
 * (`internal/mfa-keys.mts`); `~` is not base64url, so no factor's field is
 * `~g`. Every operation touches the subject's one key, so a Cluster spreads
 * subjects across its slots. A hash holding a factor carries no TTL: an
 * enrolled factor does not expire, and a `volatile-*` eviction policy may
 * drop a key with a TTL.
 *
 * A record is `<version>\n<fixed>\n<mutable>`: the version as decimal text,
 * one JSON line for what never changes after `createIf` (id, subject, kind,
 * binding, createdAt) and one for what `update` replaces (data, label,
 * lastUsedAt), so the compare-and-set is one script that never decodes the
 * JSON (`MfaFactorStoreClient`). `data` arrives sealed by the coordinator and
 * is kept byte for byte.
 *
 * A stored value that does not read back as the record written under that
 * subject and field is refused with an error quoting nothing it read: an
 * outage, never "no factor". Only a subject with no record that may count
 * opens a first binding, so a record read as absent would downgrade the
 * account.
 * See the MFA ADR (2026-09-25-multi-factor-authentication), D7 and D12.
 *
 * The factor set's generation follows core's conditional-write convention
 * (docs/adapter-surface.md, "Conditional writes"):
 *
 * - Each generation is minted here with `newStoreGeneration` and handed to
 *   the script that writes it. Each membership write keeps its answer under
 *   a replay key of its own (`<key>:w:<generation>`) until the declared clock
 *   skew past its deadline, so a copy the driver sends again answers the
 *   first copy's answer and writes nothing: no generation is issued twice
 *   (rule 8), and no write that landed answers `conflict` (rule 4).
 *   `listVersioned`, `createIf`, `removeIf` and `removeAllForSubject` are
 *   one script each (rules 1 and 2); `update` keeps `~g`.
 * - Every one of those scripts may write, so a read-only replica
 *   (`replica-read-only yes`, Redis's default) refuses it: the versioned read
 *   is answered by the primary, never such a replica (rule 2). `removeIf`,
 *   the reset and `listVersioned` declare `allow-oom`, so a full
 *   `noeviction` server still runs them; `createIf` is refused there.
 * - A write that leaves the hash holding `~g` alone keeps it as the set's
 *   tombstone for `BUNDLED_STORE_WRITE_LIFETIME_MS`, 24 hours, from that
 *   write, a reset of an already empty set included; a write that leaves a
 *   factor in it takes the expiry off (rule 6).
 * - A hash with factors and no `~g`, from a build before the set had a
 *   generation, answers `conflict` to every conditional write, and its first
 *   `listVersioned` gives it one (rule 8).
 * - Each membership write carries a deadline set at issue, `Date.now()` plus
 *   {@link WRITE_TIMEOUT_MS}, which its script compares with the server's
 *   clock before it reads or writes anything: at or past it, that copy writes
 *   nothing and the write rejects with its outcome unknown, since another
 *   copy may have committed, or may still commit within W (a server whose
 *   clock lags by the skew may judge another copy on time after a
 *   failover). The wait ends at the same timeout. So the write
 *   lifetime W is {@link REDIS_MFA_FACTOR_STORE_WRITE_LIFETIME_MS} (rule 6).
 *   Half 2 of the bound holds while the app's and Redis's clocks agree within
 *   the declared skew. A late command, whether resent, queued or stalled,
 *   writes nothing. The check bounds when a script starts: the server is
 *   assumed not to stall inside a running script, between its clock check
 *   and its write, for the whole of W.
 * - This store assumes acknowledged writes are not rolled back (persistence
 *   plus a failover setup that keeps acked writes); a deployment that accepts
 *   acked-write loss on failover also accepts that a conditional write may
 *   see a restored older generation. For MFA: acknowledged factor-set writes
 *   are not rolled back (no async-replica failover without `WAIT`, or the
 *   operator accepts that a failover may restore removed factors).
 *
 * The redis README, "MFA stores", states each for an operator.
 */

import {
	BUNDLED_STORE_WRITE_LIFETIME_MS,
	checkMfaVersionAdvances,
	consoleLogger,
	defineModule,
	isStorableExpiry,
	isStoreGeneration,
	type MfaFactorRecord,
	type MfaFactorRecordUpdate,
	type MfaFactorStore,
	newStoreGeneration,
	type StoreGeneration,
} from "@o3co/auth-provider-core";
import type { MfaFactorStoreClient } from "./clients.mjs";
import { checkRedisMfaStoreDurability } from "./internal/mfa-durability.mjs";
import { checkMfaKeyPrefix, mfaKeyPart } from "./internal/mfa-keys.mjs";
import { keyPrefixSection, redisReference } from "./internal/section.mjs";

/** The key namespace `redisMfaFactorStore.keyPrefix` defaults to. */
export const DEFAULT_REDIS_MFA_FACTOR_STORE_KEY_PREFIX = "mfaf:";

export interface RedisMfaFactorStoreOptions {
	readonly client: MfaFactorStoreClient;
	/** Outer namespace; the subject's hash tag follows it. Without a brace. Default `mfaf:`. */
	readonly keyPrefix?: string;
}

const RANGE = (what: string): RangeError => new RangeError(`MfaFactorStore (redis): ${what}`);

/** What a record this adapter cannot read is answered with. It quotes nothing it read. */
const unreadable = (): Error =>
	new Error(
		"MfaFactorStore (redis): a stored factor record is not one this adapter wrote; it is refused rather than read as no factor",
	);

const isWholeVersion = (value: unknown): value is number =>
	typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

/**
 * Whether `value` is an instant a `Date` holds as written: a whole number of
 * milliseconds within the Date range, ±8.64e15 (core's `isStorableExpiry`,
 * the range every store keeps to). Past it `new Date` answers an Invalid
 * Date, and a fraction another instant.
 */
const isInstant = (value: unknown): value is number =>
	typeof value === "number" && Number.isInteger(value) && isStorableExpiry(value);

/**
 * A date's epoch milliseconds, or a `RangeError` for one that is not a date
 * or answers a time value {@link isInstant} refuses — what a read would not
 * take back.
 */
const instantOf = (value: Date, name: string): number => {
	const ms = value instanceof Date ? value.getTime() : Number.NaN;
	if (!isInstant(ms)) throw RANGE(`${name} must be a valid date`);
	return ms;
};

const optionalInstantOf = (value: Date | undefined, name: string): number | null =>
	value === undefined ? null : instantOf(value, name);

const BINDING_NAMES = {
	password: true,
	email_proof: true,
	federated: true,
	mfa: true,
} as const satisfies Record<NonNullable<MfaFactorRecord["binding"]>, true>;
const BINDINGS: ReadonlySet<unknown> = new Set(Object.keys(BINDING_NAMES));

/**
 * Refuses, with a `RangeError`, a mutable part {@link recordOf} would refuse
 * to read: `data` not a string, `label` neither a string nor absent.
 */
function checkMutable(next: MfaFactorRecordUpdate): void {
	if (typeof next.data !== "string") throw RANGE("data must be a string");
	if (next.label !== undefined && typeof next.label !== "string") {
		throw RANGE("label must be a string or absent");
	}
}

/**
 * Refuses, with a `RangeError`, a record {@link recordOf} would refuse to
 * read: a read refuses the subject's whole list over one such record, so a
 * write of one would make every factor of the subject unreadable. The dates
 * are checked where they are written.
 */
function checkRecord(factor: MfaFactorRecord): void {
	if (typeof factor.id !== "string") throw RANGE("id must be a string");
	if (typeof factor.subject !== "string") throw RANGE("subject must be a string");
	if (typeof factor.kind !== "string") throw RANGE("kind must be a string");
	if (factor.binding !== undefined && !BINDINGS.has(factor.binding)) {
		throw RANGE('binding must be "password", "email_proof", "federated", "mfa" or absent');
	}
	if (!isWholeVersion(factor.version)) {
		throw RANGE("version must be a safe non-negative integer");
	}
	checkMutable(factor);
}

const fixedPart = (factor: MfaFactorRecord): string =>
	JSON.stringify({
		id: factor.id,
		subject: factor.subject,
		kind: factor.kind,
		binding: factor.binding ?? null,
		createdAt: instantOf(factor.createdAt, "createdAt"),
	});

const mutablePart = (next: MfaFactorRecordUpdate): string =>
	JSON.stringify({
		data: next.data,
		label: next.label ?? null,
		lastUsedAt: optionalInstantOf(next.lastUsedAt, "lastUsedAt"),
	});

const isObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * The record `value` holds, as plain data with every field named — or the
 * {@link unreadable} error, when it is not three well-formed lines, names
 * another subject or another id than the field it was read from, or holds a
 * date that is no instant a `Date` holds as written ({@link isInstant}).
 */
function recordOf(value: string, subject: string, field: string): MfaFactorRecord {
	const lines = value.split("\n");
	if (lines.length !== 3) throw unreadable();
	const [versionText, fixedText, mutableText] = lines as [string, string, string];
	if (!/^(0|[1-9][0-9]*)$/.test(versionText)) throw unreadable();
	const version = Number(versionText);
	let fixed: unknown;
	let mutable: unknown;
	try {
		fixed = JSON.parse(fixedText);
		mutable = JSON.parse(mutableText);
	} catch {
		throw unreadable();
	}
	if (!isWholeVersion(version) || !isObject(fixed) || !isObject(mutable)) throw unreadable();
	const { id, kind, binding, createdAt } = fixed;
	const { data, label, lastUsedAt } = mutable;
	if (
		typeof id !== "string" ||
		mfaKeyPart(id) !== field ||
		fixed.subject !== subject ||
		typeof kind !== "string" ||
		(binding !== null && !BINDINGS.has(binding)) ||
		!isInstant(createdAt) ||
		typeof data !== "string" ||
		(label !== null && typeof label !== "string") ||
		(lastUsedAt !== null && !isInstant(lastUsedAt))
	) {
		throw unreadable();
	}
	return {
		id,
		subject,
		kind,
		label: label ?? undefined,
		binding: (binding ?? undefined) as MfaFactorRecord["binding"],
		createdAt: new Date(createdAt),
		lastUsedAt: lastUsedAt === null ? undefined : new Date(lastUsedAt),
		version,
		data,
	};
}

/**
 * How long the adapter waits for a membership write's answer, and how far
 * past its issue, on the app's clock, the write's deadline lies: the command
 * timeout part of the write lifetime W. It matches the 1 000 ms
 * `commandTimeout` the README asks of the connection, and the least
 * `mfa.storeTimeoutMs`.
 */
const WRITE_TIMEOUT_MS = 1_000;

/**
 * The clock skew the write lifetime allows between the app's clock, which
 * sets a write's deadline, and the Redis server's, which judges it: the 1 s
 * the operator runbook asks of every replica's and Redis server's clock
 * ("Replica clocks").
 */
const CLOCK_SKEW_MS = 1_000;

/**
 * The adapter's write lifetime W (docs/adapter-surface.md, "Conditional
 * writes", rule 6): a membership write commits or fails within
 * {@link WRITE_TIMEOUT_MS} + {@link CLOCK_SKEW_MS} of its issue, while the
 * two clocks agree within the skew.
 */
export const REDIS_MFA_FACTOR_STORE_WRITE_LIFETIME_MS = WRITE_TIMEOUT_MS + CLOCK_SKEW_MS;

/** The field of a subject's hash that holds its set's generation; no factor's field is it. */
const GENERATION_FIELD = "~g";

/**
 * What a membership write its script answers `late` is answered with: its outcome is unknown,
 * never that nothing was written. The copy the server judged late wrote nothing, but another
 * copy may have committed (one the driver sent before, whose replay key has gone), or may
 * still commit within W (a server whose clock lags by the skew may judge it on time after a
 * failover).
 */
const late = (operation: string): Error =>
	new Error(
		`MfaFactorStore (redis): ${operation} was answered past its deadline; the outcome is unknown: another copy may have committed, or may still commit within W`,
	);

/** What a membership write unanswered within the write timeout is answered with: its outcome is unknown. */
const unanswered = (operation: string): Error =>
	new Error(
		`MfaFactorStore (redis): ${operation} had no answer within ${WRITE_TIMEOUT_MS} ms; it may have committed, or may still commit within W`,
	);

/**
 * `write` run with its deadline, `WRITE_TIMEOUT_MS` from now on the app's
 * clock, and its answer awaited no longer than that: past it the wait ends
 * in {@link unanswered}. Whatever reaches the server later, queued, sent
 * again after a reconnect or held by a stalled server, the script refuses.
 */
async function withDeadline<T>(
	operation: string,
	write: (deadlineMs: number) => Promise<T>,
): Promise<T> {
	const deadlineMs = Date.now() + WRITE_TIMEOUT_MS;
	let timer: ReturnType<typeof setTimeout> | undefined;
	const timeout = new Promise<never>((_, reject) => {
		timer = setTimeout(() => reject(unanswered(operation)), WRITE_TIMEOUT_MS);
		timer.unref?.();
	});
	try {
		return await Promise.race([write(deadlineMs), timeout]);
	} finally {
		clearTimeout(timer);
	}
}

/** A generation a caller hands back, or a `RangeError`: only what a store answered is one. */
function checkExpected(expected: unknown, operation: string): StoreGeneration {
	if (!isStoreGeneration(expected)) {
		throw new RangeError(`MfaFactorStore.${operation}: expected is not a store generation`);
	}
	return expected;
}

export function createRedisMfaFactorStore(options: RedisMfaFactorStoreOptions): MfaFactorStore {
	const { client } = options;
	const keyPrefix = checkMfaKeyPrefix(
		options.keyPrefix ?? DEFAULT_REDIS_MFA_FACTOR_STORE_KEY_PREFIX,
		"MfaFactorStore (redis)",
	);
	const keyOf = (subject: string): string => `${keyPrefix}{${mfaKeyPart(subject)}}`;

	/** The records a hash's fields hold, the generation's field left out. */
	const recordsOf = (
		fields: Readonly<Record<string, string>>,
		subject: string,
	): MfaFactorRecord[] =>
		Object.entries(fields).flatMap(([field, value]) =>
			field === GENERATION_FIELD ? [] : [recordOf(value, subject, field)],
		);

	/** A record's stored value, or a `RangeError` for one a read would refuse. */
	const storedValueOf = (factor: MfaFactorRecord): string => {
		checkRecord(factor);
		return `${factor.version}\n${fixedPart(factor)}\n${mutablePart(factor)}`;
	};

	/**
	 * What every membership write of `key`'s set carries: a fresh generation,
	 * the deadline, and the key its answer is kept under until then, on the
	 * set's hash tag.
	 */
	const writeOf = (key: string, deadlineMs: number) => {
		const next = newStoreGeneration();
		return { next, deadlineMs, replayKey: `${key}:w:${next}`, clockSkewMs: CLOCK_SKEW_MS };
	};

	return {
		kind: "redis",

		async list(subject) {
			return recordsOf(await client.list(keyOf(subject)), subject);
		},

		async listVersioned(subject) {
			const fields = await client.listVersioned(keyOf(subject), newStoreGeneration());
			if (Object.keys(fields).length === 0) return { items: [], generation: null };
			const generation = fields[GENERATION_FIELD];
			if (!isStoreGeneration(generation)) throw unreadable();
			return { items: recordsOf(fields, subject), generation };
		},

		async createIf(factor, expected) {
			if (expected !== null) checkExpected(expected, "createIf");
			// Refused before anything is written: whatever a read would refuse.
			const value = storedValueOf(factor);
			const key = keyOf(factor.subject);
			let next: StoreGeneration | undefined;
			const outcome = await withDeadline("createIf", (deadlineMs) => {
				const write = writeOf(key, deadlineMs);
				next = write.next;
				return client.createIf(key, mfaKeyPart(factor.id), value, { ...write, expected });
			});
			if (outcome === "late") throw late("createIf");
			return outcome === "created" ? { outcome, generation: next as StoreGeneration } : { outcome };
		},

		async removeIf(subject, id, expected) {
			checkExpected(expected, "removeIf");
			const key = keyOf(subject);
			let next: StoreGeneration | undefined;
			const outcome = await withDeadline("removeIf", (deadlineMs) => {
				const write = writeOf(key, deadlineMs);
				next = write.next;
				return client.removeIf(key, mfaKeyPart(id), {
					...write,
					tombstoneMs: BUNDLED_STORE_WRITE_LIFETIME_MS,
					expected,
				});
			});
			if (outcome === "late") throw late("removeIf");
			return outcome === "removed" ? { outcome, generation: next as StoreGeneration } : { outcome };
		},

		async update(subject, id, expectedVersion, next) {
			checkMutable(next);
			const mutable = mutablePart(next);
			// Refused before the script: the next version would be written as
			// 9007199254740992, which `recordOf` refuses, and the subject's whole
			// list would be unreadable from then on.
			checkMfaVersionAdvances(expectedVersion, "MfaFactorStore.update");
			// No stored record is at a version that is not a whole number.
			if (!isWholeVersion(expectedVersion)) return null;
			const field = mfaKeyPart(id);
			const written = await client.update(keyOf(subject), field, {
				expectedVersion: String(expectedVersion),
				nextVersion: String(expectedVersion + 1),
				mutable,
			});
			return written === null ? null : recordOf(written, subject, field);
		},

		async removeAllForSubject(subject) {
			const key = keyOf(subject);
			const outcome = await withDeadline("removeAllForSubject", (deadlineMs) =>
				client.removeAll(key, {
					...writeOf(key, deadlineMs),
					tombstoneMs: BUNDLED_STORE_WRITE_LIFETIME_MS,
				}),
			);
			if (outcome === "late") throw late("removeAllForSubject");
		},
	};
}

// --- the module ------------------------------------------------------------

/**
 * `defineModule` manifest for the Redis {@link MfaFactorStore}:
 * `mfaFactorStore` off the `mfaFactorStoreClient` slot (the shared socket
 * `makeIoredisClients` wraps or, preferably, a dedicated database or
 * instance), with its keys under `redis-mfa-factor-store.keyPrefix` (`mfaf:`),
 * its own section (strict).
 *
 * Declares no `replicaSafety`: every replica reads the one store, so a
 * composition with it may declare `core.deployment.mode = "multi"`. Before it
 * provides the store it runs the durability check
 * (`internal/mfa-durability.mts`): an `allkeys-*` eviction policy refuses the
 * boot (`mfa-factor-store-evictable`), and each warning goes to the `logger`
 * slot, or to `consoleLogger`.
 */
export const redisMfaFactorStoreModule = defineModule({
	name: "redis-mfa-factor-store",
	section: {
		schema: keyPrefixSection(DEFAULT_REDIS_MFA_FACTOR_STORE_KEY_PREFIX),
		reference: redisReference(),
		relocatedFrom: {
			redisMfaFactorStore: { to: "", environmentVariable: null },
			"redisMfaFactorStore.keyPrefix": "keyPrefix",
		},
	},
	requires: ["mfaFactorStoreClient"] as const,
	optional: ["logger"] as const,
	provides: {
		mfaFactorStore: async (deps) => {
			// Built first, so a prefix it refuses is refused before the server is asked.
			const store = createRedisMfaFactorStore({
				client: deps.mfaFactorStoreClient,
				keyPrefix: deps.section.keyPrefix,
			});
			await checkRedisMfaStoreDurability(
				"mfaFactorStore",
				() => deps.mfaFactorStoreClient.durability(),
				deps.logger ?? consoleLogger,
			);
			return store;
		},
	},
});
