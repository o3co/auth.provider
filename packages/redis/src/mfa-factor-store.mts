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
 * Redis {@link MfaFactorStore} (the MFA ADR's D7): enrolled second factors,
 * one hash per subject.
 *
 * ```text
 * <keyPrefix>{<subject>}   HASH   field <factor id> → the record
 * ```
 *
 * `<subject>` and `<factor id>` are base64url of their JSON
 * (`internal/mfa-keys.mts`). A subject's factors are one key, so every
 * operation touches one key and a Cluster spreads subjects across its slots.
 * No key carries a TTL: an enrolled factor does not expire, and a key with a
 * TTL is one a `volatile-*` eviction policy may drop (D12).
 *
 * A record is `<version>\n<fixed>\n<mutable>` — the version as decimal text,
 * then one line of JSON for what never changes after `create` (id, subject,
 * kind, binding, createdAt) and one for what `update` replaces (data, label,
 * lastUsedAt). The split is what lets the compare-and-set be one script that
 * never decodes the JSON (`MfaFactorStoreClient`). `data` is sealed by the
 * coordinator before it arrives (D11) and is kept byte for byte.
 *
 * A stored value this adapter cannot read back as the record it wrote under
 * that subject and field is refused with an error that quotes nothing it
 * read: "only zero records open a first binding" (F3), so a record read as
 * absent would downgrade the account. It is an outage, never "no factor"
 * (D12, D28).
 */

import {
	consoleLogger,
	defineModule,
	type MfaFactorRecord,
	type MfaFactorRecordUpdate,
	type MfaFactorStore,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type { MfaFactorStoreClient } from "./clients.mjs";
import { checkRedisMfaStoreDurability } from "./internal/mfa-durability.mjs";
import { checkMfaKeyPrefix, mfaKeyPart } from "./internal/mfa-keys.mjs";

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

/** A date's epoch milliseconds, or a `RangeError` for one that is not a date. */
const instantOf = (value: Date, name: string): number => {
	const ms = value instanceof Date ? value.getTime() : Number.NaN;
	if (Number.isNaN(ms)) throw RANGE(`${name} must be a valid date`);
	return ms;
};

const optionalInstantOf = (value: Date | undefined, name: string): number | null =>
	value === undefined ? null : instantOf(value, name);

const BINDINGS: ReadonlySet<unknown> = new Set(["password", "email_proof", "mfa"]);

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
		throw RANGE('binding must be "password", "email_proof", "mfa" or absent');
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

const isInstant = (value: unknown): value is number =>
	typeof value === "number" && Number.isFinite(value);

/**
 * The record `value` holds, as plain data with every field named — or the
 * {@link unreadable} error, when it is not three well-formed lines, or names
 * another subject or another id than the field it was read from.
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

const moduleConfigSchema = z.object({
	redisMfaFactorStore: z
		.object({ keyPrefix: z.string().default(DEFAULT_REDIS_MFA_FACTOR_STORE_KEY_PREFIX) })
		.default({ keyPrefix: DEFAULT_REDIS_MFA_FACTOR_STORE_KEY_PREFIX }),
});

/**
 * `defineModule` manifest for the Redis {@link MfaFactorStore} (the MFA ADR's
 * D7, D10, D12, D19): `mfaFactorStore` off the `mfaFactorStoreClient` slot —
 * the shared socket `makeIoredisClients` wraps, or a dedicated database or
 * instance, which D12 prefers — with its keys under
 * `redisMfaFactorStore.keyPrefix` (`mfaf:`).
 *
 * Declares no `replicaSafety`: every replica reads the one store, so a
 * composition with it may declare `deployment.mode = "multi"`. Before it
 * provides the store it runs D12's durability check against the server
 * (`internal/mfa-durability.mts`): an `allkeys-*` eviction policy refuses the
 * boot (`mfa-factor-store-evictable`); RDB snapshots without AOF
 * (`mfa_factor_store_lossy`), no persistence (`mfa_factor_store_volatile`)
 * and a server that refuses `CONFIG` (`mfa_factor_store_durability_unchecked`)
 * are each one warning on the `logger` slot, or on `consoleLogger`.
 */
export const redisMfaFactorStoreModule = defineModule({
	name: "redis-mfa-factor-store",
	requires: ["mfaFactorStoreClient", "config"] as const,
	optional: ["logger"] as const,
	configSchema: moduleConfigSchema,
	provides: {
		mfaFactorStore: async (deps) => {
			const { keyPrefix } = moduleConfigSchema.parse(deps.config ?? {}).redisMfaFactorStore;
			// Built first, so a prefix it refuses is refused before the server is asked.
			const store = createRedisMfaFactorStore({ client: deps.mfaFactorStoreClient, keyPrefix });
			await checkRedisMfaStoreDurability(
				"mfaFactorStore",
				() => deps.mfaFactorStoreClient.durability(),
				deps.logger ?? consoleLogger,
			);
			return store;
		},
	},
});
