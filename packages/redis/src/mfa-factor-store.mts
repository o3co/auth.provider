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
 * ```
 *
 * `<subject>` and `<factor id>` are base64url of their JSON
 * (`internal/mfa-keys.mts`). Every operation touches the subject's one key, so
 * a Cluster spreads subjects across its slots. No key carries a TTL: an
 * enrolled factor does not expire, and a `volatile-*` eviction policy may drop
 * a key with a TTL.
 *
 * A record is `<version>\n<fixed>\n<mutable>`: the version as decimal text,
 * one JSON line for what never changes after `create` (id, subject, kind,
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
 */

import {
	checkMfaVersionAdvances,
	consoleLogger,
	defineModule,
	isStorableExpiry,
	type MfaFactorRecord,
	type MfaFactorRecordUpdate,
	type MfaFactorStore,
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
function checkRecord(record: MfaFactorRecord): void {
	if (typeof record.id !== "string") throw RANGE("id must be a string");
	if (typeof record.subject !== "string") throw RANGE("subject must be a string");
	if (typeof record.kind !== "string") throw RANGE("kind must be a string");
	if (record.binding !== undefined && !BINDINGS.has(record.binding)) {
		throw RANGE('binding must be "password", "email_proof", "federated", "mfa" or absent');
	}
	if (!isWholeVersion(record.version)) {
		throw RANGE("version must be a safe non-negative integer");
	}
	checkMutable(record);
}

const fixedPart = (record: MfaFactorRecord): string =>
	JSON.stringify({
		id: record.id,
		subject: record.subject,
		kind: record.kind,
		binding: record.binding ?? null,
		createdAt: instantOf(record.createdAt, "createdAt"),
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

export function createRedisMfaFactorStore(options: RedisMfaFactorStoreOptions): MfaFactorStore {
	const { client } = options;
	const keyPrefix = checkMfaKeyPrefix(
		options.keyPrefix ?? DEFAULT_REDIS_MFA_FACTOR_STORE_KEY_PREFIX,
		"MfaFactorStore (redis)",
	);
	const keyOf = (subject: string): string => `${keyPrefix}{${mfaKeyPart(subject)}}`;

	return {
		kind: "redis",

		async list(subject) {
			const fields = await client.list(keyOf(subject));
			return Object.entries(fields).map(([field, value]) => recordOf(value, subject, field));
		},

		async create(record) {
			// Refused before anything is written: whatever a read would refuse.
			checkRecord(record);
			const value = `${record.version}\n${fixedPart(record)}\n${mutablePart(record)}`;
			if (!(await client.create(keyOf(record.subject), mfaKeyPart(record.id), value))) {
				throw new Error("an MFA factor record with this id already exists for the subject");
			}
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

		async remove(subject, id) {
			await client.remove(keyOf(subject), mfaKeyPart(id));
		},

		async removeAllForSubject(subject) {
			await client.removeAll(keyOf(subject));
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
