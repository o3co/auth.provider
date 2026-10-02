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
 * Issuing a subject's recovery codes (the MFA ADR's D22, D25): a set made by
 * the installed recovery-code factor, written as one `recovery_code` record
 * sealed to it, as the binding it follows authorized it, under the subject's
 * lease (`factorSet.mts`), through the subject's factor set the lease hands
 * it — each write applied only while the set stands as the lease's read, or
 * this binding's own writes since, left it. Never throws: a set that cannot
 * be made, written or shown is answered not issued, with why, so what it
 * follows stands.
 *
 * - The sets that stand are those among the records read under the lease.
 * - A set's generation is one past the newest it replaces — the subject's
 *   recovery-set floor, or a readable set's generation, whichever is higher
 *   (a set it cannot read counts for nothing) — and the floor is raised to
 *   it once it is written, so every set that stood is retired: a
 *   verification refuses a set below the floor. A floor that cannot be read
 *   writes nothing; one that cannot be raised removes the new set and keeps
 *   those that stood — a removal that fails too is said beside it, the set
 *   left stored and unshown.
 * - A set whose write finds the subject's factor set changed since it was
 *   read — another write landed, which under the lease only a writer past
 *   its own lease can make — is not written: not issued, as the loser
 *   (`conflict`), the floor untouched.
 * - Every set that stood, readable or not, is then removed, until one
 *   removal finds the factor set changed: the rest are left. One that cannot
 *   be removed, or is left, is a retired set still stored, answered with why
 *   (`unreplaced`); it never undoes the new set. Each set left stays retired
 *   by the floor, and the next replacement removes it.
 * - Last, the set is marked shown by compare-and-set at the version it was
 *   written; only once it is are its codes answered, so codes are never
 *   answered while the set says it was not shown. A mark that fails, or
 *   finds the set changed, shows nothing, and leaves the set unshown.
 *   `issueRecoveryCodes` marks it at once, through the writes it is handed;
 *   `writeRecoveryCodes` leaves the mark to the answer that carries the
 *   codes (`show`), for a caller whose answer may still be another one. The
 *   mark needs no lease: a writer that replaced, removed or changed the set
 *   since fails it. A set is marked once, so its codes are answered once.
 *
 * `mfa.maxFactorsPerSubject` counts what stands once a replacement is
 * complete: the sets a new one replaces are not counted, though they are
 * removed only after it is written. While a sweep is stopped, the subject
 * may hold one record past the limit, every set left retired.
 *
 * A binding by `password` — no account-email proof was asked — replaces
 * nothing: whoever holds the password and one code could make it, so the
 * sets that stood are kept, the new one written at the newest generation
 * beside them, the floor untouched, and the owner's remaining codes stay
 * usable (D25's amendment). Wherever the binding is made, this is the one
 * rule.
 */

import { randomBytes } from "node:crypto";
import {
	isMfaFactorUpdateWritten,
	type MfaFactor,
	type MfaFactorRecord,
	type MfaFactorRecordUpdate,
	type MfaFactorResolver,
	type MfaFactorStore,
} from "@o3co/auth-provider-core";
import { OUTSIDE_CONTRACT } from "../ceremony.mjs";
import type { MfaFactorSetWriter, MfaFactorSetWrites } from "../factorSet.mjs";
import type { MfaSealing } from "../sealing.mjs";
import {
	generateRecoveryCodes,
	RECOVERY_CODE_FACTOR_KIND,
	recoverySetGeneration,
	shownRecoverySet,
} from "./factor.mjs";

/** Why a set that stood may still be stored beside the new one: kept for a `password` binding, or retired and not removed. */
export type MfaUnreplacedRecoveryCodes =
	| { readonly kept: "password_binding" }
	| { readonly cause: unknown };

/**
 * What issuing came to: nothing while the factor is off, or not issued, with
 * why — `conflict` when the subject's factor set changed before the new set
 * was written; or the codes to answer once, whether the new set replaces one
 * — `regenerated`: one stood — and why one may still be stored
 * (`unreplaced`).
 */
export type MfaIssuedRecoveryCodes =
	| {
			readonly issued: true;
			readonly codes: readonly string[];
			readonly regenerated: boolean;
			readonly unreplaced?: MfaUnreplacedRecoveryCodes;
	  }
	| { readonly issued: false; readonly cause: unknown; readonly conflict?: true }
	| undefined;

/** A set written and not yet shown: its codes are reached through `show` alone, which marks it shown (see this file's header). Never throws. */
export interface MfaUnshownRecoveryCodes {
	readonly written: "unshown";
	show(): Promise<Exclude<MfaIssuedRecoveryCodes, undefined>>;
}

/** What writing a set came to: nothing while the factor is off, not issued with why, or the set written unshown. */
export type MfaWrittenRecoveryCodes =
	| MfaUnshownRecoveryCodes
	| Extract<MfaIssuedRecoveryCodes, { readonly issued: false }>
	| undefined;

export interface IssueRecoveryCodesOptions {
	readonly factors: MfaFactorResolver;
	/** The subject's factor set and recovery-set floor, as the subject's lease hands them. */
	readonly writes: Pick<MfaFactorSetWrites, "factors" | "recoverySetFloor">;
	readonly sealing: MfaSealing;
	readonly subject: string;
	/** What authorized the binding the set is issued beside: `mfa` for a regeneration. */
	readonly binding: NonNullable<MfaFactorRecord["binding"]>;
	readonly nowMs: number;
}

export interface WriteRecoveryCodesOptions extends IssueRecoveryCodesOptions {
	/** The factor store `show` marks the set shown through, once the lease that wrote it is released. */
	readonly markedThrough: Pick<MfaFactorStore, "update">;
}

/** Whether a set issued beside a binding by `binding` replaces the sets that stood: the one rule (see this file's header). */
export const replacesStandingSets = (binding: NonNullable<MfaFactorRecord["binding"]>): boolean =>
	binding !== "password";

/** What a write of the subject's factor set that found it changed since its read is answered with. */
const SET_CHANGED = "the subject's factor set changed since it was read: another write landed";

/** A new set for `options.subject`, marked shown at once through the writes it is handed (see this file's header). */
export async function issueRecoveryCodes(
	options: IssueRecoveryCodesOptions,
): Promise<MfaIssuedRecoveryCodes> {
	const written = await writeSet(options, (id, expectedVersion, next) =>
		options.writes.factors.update(id, expectedVersion, next),
	);
	return written !== undefined && "written" in written ? written.show() : written;
}

/** A new set for `options.subject`, written unshown for its answer to mark (see this file's header). */
export async function writeRecoveryCodes(
	options: WriteRecoveryCodesOptions,
): Promise<MfaWrittenRecoveryCodes> {
	const { markedThrough, subject } = options;
	return writeSet(options, (id, expectedVersion, next) =>
		markedThrough.update(subject, id, expectedVersion, next),
	);
}

/** A record's update by compare-and-set: the subject's record `id`, at `expectedVersion`. */
type MarkShown = (
	id: string,
	expectedVersion: number,
	next: MfaFactorRecordUpdate,
) => Promise<MfaFactorRecord | null>;

/** A new set written unshown, its mark through `mark` (see this file's header). */
async function writeSet(
	options: IssueRecoveryCodesOptions,
	mark: MarkShown,
): Promise<MfaWrittenRecoveryCodes> {
	const { factors, writes, sealing, subject } = options;
	const { factors: set, recoverySetFloor } = writes;
	const factor = factors.get(RECOVERY_CODE_FACTOR_KIND);
	if (factor === undefined) return undefined;
	const replacing = replacesStandingSets(options.binding);
	const id = randomBytes(16).toString("base64url");
	try {
		const digests = sealing.digestsFor(RECOVERY_CODE_FACTOR_KIND);
		const standing = set.records.filter((record) => record.kind === RECOVERY_CODE_FACTOR_KIND);
		const floor = await recoverySetFloor.read(subject);
		const newest = Math.max(floor, ...standing.map((record) => generationOf(record)));
		const generation = replacing ? newest + 1 : newest;
		const made = generateRecoveryCodes(factor, digests, generation);
		if (made === undefined) return undefined;
		const binding = { subject, id, kind: RECOVERY_CODE_FACTOR_KIND };
		const shown = shownRecoverySet(made.data);
		if (shown === undefined) throw new TypeError("the factor issued data that is not a set");
		const sealedShown = sealing.sealFactorData(binding, shown);
		const created = await set.create({
			id,
			subject,
			kind: RECOVERY_CODE_FACTOR_KIND,
			label: undefined,
			binding: options.binding,
			createdAt: new Date(options.nowMs),
			lastUsedAt: undefined,
			version: 0,
			data: sealing.sealFactorData(binding, made.data),
		});
		if (created === "changed") {
			return { issued: false, cause: new Error(SET_CHANGED), conflict: true };
		}

		let unreplaced: MfaUnreplacedRecoveryCodes | undefined;
		if (!replacing) {
			if (standing.length > 0) unreplaced = { kept: "password_binding" };
		} else {
			try {
				await recoverySetFloor.raise(subject, generation);
			} catch (cause) {
				const unremoved = await removeEach(set, [id]);
				return {
					issued: false,
					cause:
						unremoved === undefined
							? cause
							: new AggregateError(
									[cause, unremoved.cause],
									"the recovery-set floor was not raised, and the new set could not be removed: it stays stored, unshown",
								),
				};
			}
			unreplaced = await removeEach(
				set,
				standing.map((record) => record.id),
			);
		}

		const issued = {
			issued: true as const,
			codes: made.codes,
			regenerated: standing.length > 0,
			...(unreplaced === undefined ? {} : { unreplaced }),
		};
		return {
			written: "unshown",
			show: () => markShown(mark, subject, id, sealedShown, issued),
		};
	} catch (cause) {
		return { issued: false, cause };
	}

	/** The generation of `record`'s set; -1 for one that cannot be read, which counts for nothing. */
	function generationOf(record: MfaFactorRecord): number {
		const opened = sealing.openFactorData(
			{ subject, id: record.id, kind: record.kind },
			record.data,
		);
		return opened.state === "ok"
			? (recoverySetGeneration(factor as MfaFactor, opened.value) ?? -1)
			: -1;
	}
}

/**
 * The set `id` marked shown by compare-and-set at the version it was written,
 * then `issued`, its codes; not issued, with why, when the mark fails or finds
 * the set changed. Never throws.
 */
async function markShown(
	mark: MarkShown,
	subject: string,
	id: string,
	sealedShown: string,
	issued: Extract<MfaIssuedRecoveryCodes, { readonly issued: true }>,
): Promise<Exclude<MfaIssuedRecoveryCodes, undefined>> {
	try {
		const marked: unknown = await mark(id, 0, {
			data: sealedShown,
			label: undefined,
			lastUsedAt: undefined,
		});
		if (marked === null) {
			return { issued: false, cause: new Error("the set changed before it was marked shown") };
		}
		if (
			!isMfaFactorUpdateWritten(marked, {
				subject,
				id,
				expectedVersion: 0,
				next: { data: sealedShown },
			})
		) {
			return { issued: false, cause: OUTSIDE_CONTRACT };
		}
		return issued;
	} catch (cause) {
		return { issued: false, cause };
	}
}

/**
 * Each of `ids` removed from `set`: `undefined` once all are, else the first
 * failure. A removal that finds the set changed leaves the rest: every later
 * one would find it so.
 */
async function removeEach(
	set: MfaFactorSetWriter,
	ids: readonly string[],
): Promise<{ readonly cause: unknown } | undefined> {
	let failed: { readonly cause: unknown } | undefined;
	for (const id of ids) {
		try {
			if ((await set.remove(id)) === "changed") return failed ?? { cause: new Error(SET_CHANGED) };
		} catch (cause) {
			failed ??= { cause };
		}
	}
	return failed;
}
