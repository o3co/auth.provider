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
 * - `unreadable`: its data does not open, a key that left the ring included.
 * - `exhausted`: a recovery-code set whose data opened and holds no code
 *   left. It stays on record, for audit.
 * - `usable`: anything else.
 *
 * Three judgments stay apart:
 * - whether a factor can be presented — offered at a challenge or a
 *   step-up: `usable` alone (`holdsUsableRecord`);
 * - whether a login asks for a second factor: a record serves
 *   (`recordServes`) in every state but `exhausted`, so one the provider
 *   cannot read — a TOTP whose key is lost among them — or whose kind it no
 *   longer installs fails closed and asks;
 * - whether a first binding may open: `mayCount` (`firstBinding.mts`), which
 *   reads no data.
 */

import type {
	MfaFactor,
	MfaFactorData,
	MfaFactorRecord,
	MfaFactorResolver,
} from "@o3co/auth-provider-core";
import { isExhaustedRecoverySet } from "./recovery/factor.mjs";
import type { MfaSealing } from "./sealing.mjs";

/** What a record is read over: the installed factors and the key ring's sealing. */
export interface MfaRecordContext {
	readonly factors: MfaFactorResolver;
	readonly sealing: MfaSealing;
}

/** A record as read (this file's header), with the factor of its kind and its data where they are had. */
export type MfaRecordReading =
	| { readonly state: "not_installed" }
	| { readonly state: "unreadable"; readonly factor: MfaFactor }
	| {
			readonly state: "usable" | "exhausted";
			readonly factor: MfaFactor;
			readonly data: MfaFactorData;
	  };

/** `record` of `subject`, read over `context`. */
export function readFactorRecord(
	context: MfaRecordContext,
	subject: string,
	record: Pick<MfaFactorRecord, "id" | "kind" | "data">,
): MfaRecordReading {
	const factor = context.factors.get(record.kind);
	if (factor === undefined) return { state: "not_installed" };
	const opened = context.sealing.openFactorData(
		{ subject, id: record.id, kind: record.kind },
		record.data,
	);
	if (opened.state !== "ok") return { state: "unreadable", factor };
	return {
		state: isExhaustedRecoverySet(factor, opened.value) ? "exhausted" : "usable",
		factor,
		data: opened.value,
	};
}

/** Whether `record` serves a decision: every state but `exhausted`. */
export const recordServes = (
	context: MfaRecordContext,
	subject: string,
	record: Pick<MfaFactorRecord, "id" | "kind" | "data">,
): boolean => readFactorRecord(context, subject, record).state !== "exhausted";

/** Whether `subject` holds a usable record among `records` — one whose factor counts, when `options.counting` asks it. */
export const holdsUsableRecord = (
	context: MfaRecordContext,
	subject: string,
	records: readonly Pick<MfaFactorRecord, "id" | "kind" | "data">[],
	options: { readonly counting: boolean },
): boolean =>
	records.some((record) => {
		const read = readFactorRecord(context, subject, record);
		return read.state === "usable" && (!options.counting || read.factor.counting === true);
	});

/** The subject's records, oldest first: the order a page lists them and a request names them. */
export const byAge = (a: MfaFactorRecord, b: MfaFactorRecord): number =>
	a.createdAt.getTime() - b.createdAt.getTime() || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
