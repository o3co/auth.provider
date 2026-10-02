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
 * The one reading of what a subject's factor record can do now, for the
 * decisions made over the records and for the account page's list.
 *
 * - `not_installed`: no installed factor verifies its kind.
 * - `unreadable`: its data does not open, or a digest it holds names a key
 *   the ring no longer holds (`keyId`, when the key is known).
 * - `retired`, read only over a subject's records as `readSubjectRecords`
 *   reads them: a recovery-code set below the subject's recovery-set floor,
 *   replaced by a newer set and kept until it is removed. Its codes verify
 *   nothing.
 * - `exhausted`: a recovery-code set whose data opened and holds no code
 *   left. It stays on record, for audit.
 * - `address_changed`, read for a signed-in session alone
 *   (`readFactorRecordAt`): an email factor whose recorded digest is not
 *   the address of the session's login `User`. One with no readable digest,
 *   or beside a `User` with no address, is `unreadable`.
 * - `usable`: anything else.
 *
 * The judgments made over these stay apart:
 * - what a transaction offers (`isOffered`): every record but `not_installed`,
 *   `exhausted` and `retired` — an `unreadable` one is offered, and its
 *   verification is the outage. A floor that cannot be read reads every set
 *   as it would without one: the offer locks nobody out, and the
 *   verification, which reads the floor itself, refuses a retired set;
 * - whether the subject holds a factor it can use — a step-up's
 *   `no_qualifying_factor`, a login reopened under `required`: `usable`
 *   alone (`holdsUsableRecord`);
 * - whether a password login asks for a second factor over a record
 *   (`asksForSecondFactor`): every state but `exhausted` and `retired`, so
 *   one the provider cannot read — a TOTP whose key is lost among them — or
 *   whose kind it no longer installs fails closed and asks;
 * - every reading that judges a recovery set — the offers, the list, a
 *   step-up's `no_qualifying_factor`, a password login's ask — reads the
 *   subject's records through `readSubjectRecords`, the one place the floor
 *   and the records are read in order, so all agree on what is usable;
 * - whether a first binding may open: `mayCount` (`firstBinding.mts`), which
 *   reads no data.
 */

import type {
	MfaFactor,
	MfaFactorData,
	MfaFactorRecord,
	MfaFactorResolver,
} from "@o3co/auth-provider-core";
import { enrolledAddressDigest } from "./email/factor.mjs";
import { matchesRecordedAddress } from "./mail.mjs";
import {
	isExhaustedRecoverySet,
	isRecoveryCodeFactor,
	isRetiredRecoverySet,
	RECOVERY_CODE_FACTOR_KIND,
	recoverySetKeyIds,
} from "./recovery/factor.mjs";
import type { MfaSealing } from "./sealing.mjs";

/** What a record is read over: the installed factors and the key ring's sealing. */
export interface MfaRecordContext {
	readonly factors: MfaFactorResolver;
	readonly sealing: MfaSealing;
	/** The subject's recovery-set floor, where it was read: a set below it is `retired`. */
	readonly recoverySetFloor?: number;
}

/** A record as read (this file's header), with the factor of its kind and its data where they are had. */
export type MfaRecordReading =
	| { readonly state: "not_installed" }
	| { readonly state: "unreadable"; readonly factor: MfaFactor; readonly keyId?: string }
	| {
			readonly state: "usable" | "exhausted" | "address_changed" | "retired";
			readonly factor: MfaFactor;
			readonly data: MfaFactorData;
	  };

type ReadRecord = Pick<MfaFactorRecord, "id" | "kind" | "data">;

/** `record` of `subject`, read over `context`; never `address_changed`. */
export function readFactorRecord(
	context: MfaRecordContext,
	subject: string,
	record: ReadRecord,
): MfaRecordReading {
	const factor = context.factors.get(record.kind);
	if (factor === undefined) return { state: "not_installed" };
	const opened = context.sealing.openFactorData(
		{ subject, id: record.id, kind: record.kind },
		record.data,
	);
	if (opened.state === "key_unavailable") {
		return { state: "unreadable", factor, keyId: opened.keyId };
	}
	if (opened.state !== "ok") return { state: "unreadable", factor };
	const floor = context.recoverySetFloor;
	if (floor !== undefined && isRetiredRecoverySet(factor, opened.value, floor)) {
		return { state: "retired", factor, data: opened.value };
	}
	const missing = recoverySetKeyIds(factor, opened.value)?.find(
		(keyId) => !context.sealing.holdsKey(keyId),
	);
	if (missing !== undefined) return { state: "unreadable", factor, keyId: missing };
	return {
		state: isExhaustedRecoverySet(factor, opened.value) ? "exhausted" : "usable",
		factor,
		data: opened.value,
	};
}

/** `record` of `subject`, read for a signed-in session whose login `User` holds `address`. */
export function readFactorRecordAt(
	context: MfaRecordContext,
	subject: string,
	record: ReadRecord,
	address: unknown,
): MfaRecordReading {
	const read = readFactorRecord(context, subject, record);
	if (read.state !== "usable") return read;
	const recorded = enrolledAddressDigest(read.factor, read.data);
	if (recorded === undefined) return read;
	if (recorded === null) return { state: "unreadable", factor: read.factor };
	const compared = matchesRecordedAddress(
		context.sealing.digestsFor(record.kind),
		address,
		recorded,
	);
	if (compared === "match") return read;
	if (compared === "mismatch") return { ...read, state: "address_changed" };
	return compared === "no_address"
		? { state: "unreadable", factor: read.factor }
		: { state: "unreadable", factor: read.factor, keyId: compared.keyUnavailable };
}

/** Whether a transaction offers a record read as `read`: every state but `not_installed`, `exhausted` and `retired`. */
export const isOffered = (read: MfaRecordReading): boolean =>
	read.state !== "not_installed" && read.state !== "exhausted" && read.state !== "retired";

/** A subject's records as one reading holds them, and the context they are read over — the recovery-set floor in it where it was read. */
export interface MfaSubjectRecords {
	readonly subject: string;
	readonly context: MfaRecordContext;
	readonly records: readonly MfaFactorRecord[];
}

/** What `readSubjectRecords` reads through. */
export interface MfaSubjectRecordsReaders {
	/** The subject's records; throws for a store that cannot answer. */
	readonly list: (subject: string) => Promise<readonly MfaFactorRecord[]>;
	/** The subject's recovery-set floor, bounded; throws for one that cannot be read. */
	readonly recoverySetFloor: (subject: string) => Promise<number>;
	/** Told of a floor that could not be read: said at warn. */
	readonly floorUnread: (subject: string, cause: unknown) => void;
}

/**
 * `subject`'s records, read for a judgment over them, with the floor its
 * recovery-code sets are held to. The records are listed; holding no set of
 * the installed recovery-code factor, no floor is read. Otherwise the floor
 * is read, and when it retires a set listed, the records are listed again —
 * a floor read after a listing may postdate a regeneration whose new set the
 * listing missed, but a regeneration writes its set before it raises the
 * floor, so the listing after the floor holds it. A floor that cannot be
 * read is told to `floorUnread` and reads every set as without one, so no
 * outage hides a way in. A listing that fails throws.
 */
export async function readSubjectRecords(
	context: MfaRecordContext,
	subject: string,
	readers: MfaSubjectRecordsReaders,
): Promise<MfaSubjectRecords> {
	const records = await readers.list(subject);
	const factor = context.factors.get(RECOVERY_CODE_FACTOR_KIND);
	if (
		factor === undefined ||
		!isRecoveryCodeFactor(factor) ||
		!records.some((record) => record.kind === RECOVERY_CODE_FACTOR_KIND)
	) {
		return { subject, context, records };
	}
	let floor: number;
	try {
		floor = await readers.recoverySetFloor(subject);
	} catch (cause) {
		readers.floorUnread(subject, cause);
		return { subject, context, records };
	}
	const floored: MfaRecordContext = { ...context, recoverySetFloor: floor };
	const retires = records.some(
		(record) => readFactorRecord(floored, subject, record).state === "retired",
	);
	return {
		subject,
		context: floored,
		records: retires ? await readers.list(subject) : records,
	};
}

/** Whether the subject `read` holds a usable record (`holdsUsableRecord`, over its context). */
export const holdsUsableIn = (
	read: MfaSubjectRecords,
	options: { readonly counting: boolean },
): boolean => holdsUsableRecord(read.context, read.subject, read.records, options);

/** Whether a password login asks for a second factor over `record`: every state but `exhausted` and `retired`. */
export const asksForSecondFactor = (
	context: MfaRecordContext,
	subject: string,
	record: ReadRecord,
): boolean => {
	const { state } = readFactorRecord(context, subject, record);
	return state !== "exhausted" && state !== "retired";
};

/** Whether `subject` holds a usable record among `records` — one whose factor counts, when `options.counting` asks it. */
export const holdsUsableRecord = (
	context: MfaRecordContext,
	subject: string,
	records: readonly ReadRecord[],
	options: { readonly counting: boolean },
): boolean =>
	records.some((record) => {
		const read = readFactorRecord(context, subject, record);
		return read.state === "usable" && (!options.counting || read.factor.counting === true);
	});
