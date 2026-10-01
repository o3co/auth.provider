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
 * - `exhausted`: a recovery-code set whose data opened and holds no code
 *   left. It stays on record, for audit.
 * - `address_changed`, read for a signed-in session alone
 *   (`readFactorRecordAt`): an email factor whose recorded digest is not
 *   the address of the session's login `User`. One with no readable digest,
 *   or beside a `User` with no address, is `unreadable`.
 * - `usable`: anything else.
 *
 * The judgments made over these stay apart:
 * - what a transaction offers (`isOffered`): every record but `not_installed`
 *   and `exhausted` — an `unreadable` one is offered, and its verification
 *   is the outage;
 * - whether the subject holds a factor it can use — a step-up's
 *   `no_qualifying_factor`, a login reopened under `required`: `usable`
 *   alone (`holdsUsableRecord`);
 * - whether a password login asks for a second factor over a record
 *   (`asksForSecondFactor`): every state but `exhausted`, so one the
 *   provider cannot read — a TOTP whose key is lost among them — or whose
 *   kind it no longer installs fails closed and asks;
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
import { isExhaustedRecoverySet, recoverySetKeyIds } from "./recovery/factor.mjs";
import type { MfaSealing } from "./sealing.mjs";

/** What a record is read over: the installed factors and the key ring's sealing. */
export interface MfaRecordContext {
	readonly factors: MfaFactorResolver;
	readonly sealing: MfaSealing;
}

/** A record as read (this file's header), with the factor of its kind and its data where they are had. */
export type MfaRecordReading =
	| { readonly state: "not_installed" }
	| { readonly state: "unreadable"; readonly factor: MfaFactor; readonly keyId?: string }
	| {
			readonly state: "usable" | "exhausted" | "address_changed";
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

/** Whether a transaction offers a record read as `read`: every state but `not_installed` and `exhausted`. */
export const isOffered = (read: MfaRecordReading): boolean =>
	read.state !== "not_installed" && read.state !== "exhausted";

/** Whether a password login asks for a second factor over `record`: every state but `exhausted`. */
export const asksForSecondFactor = (
	context: MfaRecordContext,
	subject: string,
	record: ReadRecord,
): boolean => readFactorRecord(context, subject, record).state !== "exhausted";

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
