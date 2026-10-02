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
 * lease (`factorSet.mts`), whose writes it is handed. Never throws: a set
 * that cannot be made, written or shown is answered not issued, with why,
 * so what it follows stands.
 *
 * - A set's generation is one past the newest it replaces — the subject's
 *   recovery-set floor, or a readable set's generation, whichever is higher
 *   (a set it cannot read counts for nothing) — and the floor is raised to
 *   it once it is written, so every set that stood is retired: a
 *   verification refuses a set below the floor. A floor that cannot be read
 *   writes nothing; one that cannot be raised removes the new set and keeps
 *   those that stood — a removal that fails too is said beside it, the set
 *   left stored and unshown.
 * - Every set listed before the write, readable or not, is then removed; a
 *   set written after the listing (another binding's) never is. One that
 *   cannot be removed, or a listing that failed, leaves a retired set
 *   stored, answered with why (`unreplaced`); it never undoes the new set.
 * - The records are read again after: a readable set of another writer at
 *   the new set's generation or a later one wins — the new set is removed and
 *   answered as the loser (`conflict`), shown to nobody. Whichever of two
 *   writers reads the other after its own write yields, so two never both
 *   stand; both may yield. Records that cannot be read again show nothing.
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
	type MfaFactorResolver,
	type MfaFactorStore,
} from "@o3co/auth-provider-core";
import { OUTSIDE_CONTRACT } from "../ceremony.mjs";
import type { MfaFactorSetWrites } from "../factorSet.mjs";
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
 * why — `conflict` when another writer's set won; or the codes to answer once,
 * whether the new set replaces one — `regenerated`: one stood, or could not
 * be ruled out — and why one may still be stored (`unreplaced`).
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
	readonly issued: "unshown";
	show(): Promise<Exclude<MfaIssuedRecoveryCodes, undefined>>;
}

/** What writing a set came to: nothing while the factor is off, not issued with why, or the set written unshown. */
export type MfaWrittenRecoveryCodes =
	| MfaUnshownRecoveryCodes
	| Extract<MfaIssuedRecoveryCodes, { readonly issued: false }>
	| undefined;

export interface IssueRecoveryCodesOptions {
	readonly factors: MfaFactorResolver;
	/** The factor store and the subject's recovery-set floor, as the subject's lease hands them. */
	readonly writes: Pick<MfaFactorSetWrites, "factorStore" | "recoverySetFloor">;
	readonly sealing: MfaSealing;
	readonly subject: string;
	/** What authorized the binding the set is issued beside: `mfa` for a regeneration. */
	readonly binding: NonNullable<MfaFactorRecord["binding"]>;
	readonly nowMs: number;
	/** The subject's records as the caller read them under the same lease, just before: not listed again. */
	readonly listed?: readonly MfaFactorRecord[];
}

export interface WriteRecoveryCodesOptions extends IssueRecoveryCodesOptions {
	/** The factor store `show` marks the set shown through: the lease's while it is held, else one outside it. */
	readonly markedThrough: Pick<MfaFactorStore, "update">;
}

/** Whether a set issued beside a binding by `binding` replaces the sets that stood: the one rule (see this file's header). */
export const replacesStandingSets = (binding: NonNullable<MfaFactorRecord["binding"]>): boolean =>
	binding !== "password";

/** Thrown inside issuing when another writer's set won. */
class LostToAnotherSet extends Error {}

/** A new set for `options.subject`, marked shown at once (see this file's header). */
export async function issueRecoveryCodes(
	options: IssueRecoveryCodesOptions,
): Promise<MfaIssuedRecoveryCodes> {
	const written = await writeRecoveryCodes({
		...options,
		markedThrough: options.writes.factorStore,
	});
	return written?.issued === "unshown" ? written.show() : written;
}

/** A new set for `options.subject`, written unshown for its answer to mark (see this file's header). */
export async function writeRecoveryCodes(
	options: WriteRecoveryCodesOptions,
): Promise<MfaWrittenRecoveryCodes> {
	const { factors, writes, sealing, subject } = options;
	const { factorStore, recoverySetFloor } = writes;
	const factor = factors.get(RECOVERY_CODE_FACTOR_KIND);
	if (factor === undefined) return undefined;
	const replacing = replacesStandingSets(options.binding);
	const id = randomBytes(16).toString("base64url");
	try {
		const digests = sealing.digestsFor(RECOVERY_CODE_FACTOR_KIND);
		const standing =
			options.listed === undefined
				? await setsOf(factorStore, subject)
				: { records: setsAmong(options.listed) };
		const floor = await recoverySetFloor.read(subject);
		const newest = Math.max(
			floor,
			...("records" in standing ? standing.records.map((record) => generationOf(record)) : []),
		);
		const generation = replacing ? newest + 1 : newest;
		const set = generateRecoveryCodes(factor, digests, generation);
		if (set === undefined) return undefined;
		const binding = { subject, id, kind: RECOVERY_CODE_FACTOR_KIND };
		const shown = shownRecoverySet(set.data);
		if (shown === undefined) throw new TypeError("the factor issued data that is not a set");
		const sealedShown = sealing.sealFactorData(binding, shown);
		await factorStore.create({
			id,
			subject,
			kind: RECOVERY_CODE_FACTOR_KIND,
			label: undefined,
			binding: options.binding,
			createdAt: new Date(options.nowMs),
			lastUsedAt: undefined,
			version: 0,
			data: sealing.sealFactorData(binding, set.data),
		});

		let unreplaced: MfaUnreplacedRecoveryCodes | undefined;
		if (!replacing) {
			if ("cause" in standing || standing.records.length > 0) {
				unreplaced = { kept: "password_binding" };
			}
		} else {
			try {
				await recoverySetFloor.raise(subject, generation);
			} catch (cause) {
				const unremoved = await removeEach(factorStore, subject, [id]);
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
			if ("cause" in standing) {
				unreplaced = { cause: standing.cause };
			} else {
				const failed = await removeEach(
					factorStore,
					subject,
					standing.records.map((record) => record.id),
				);
				if (failed !== undefined) unreplaced = failed;
			}
			const after = await setsOf(factorStore, subject);
			if ("cause" in after) throw after.cause;
			const winner = after.records.find(
				(record) => record.id !== id && generationOf(record) >= generation,
			);
			if (winner !== undefined) throw new LostToAnotherSet("another set of the subject's won");
		}

		const issued = {
			issued: true as const,
			codes: set.codes,
			regenerated: "cause" in standing || standing.records.length > 0,
			...(unreplaced === undefined ? {} : { unreplaced }),
		};
		return {
			issued: "unshown",
			show: () => markShown(options.markedThrough, subject, id, sealedShown, issued),
		};
	} catch (cause) {
		if (cause instanceof LostToAnotherSet) {
			await removeEach(factorStore, subject, [id]);
			return { issued: false, cause, conflict: true };
		}
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
	factorStore: Pick<MfaFactorStore, "update">,
	subject: string,
	id: string,
	sealedShown: string,
	issued: Extract<MfaIssuedRecoveryCodes, { readonly issued: true }>,
): Promise<Exclude<MfaIssuedRecoveryCodes, undefined>> {
	try {
		const marked: unknown = await factorStore.update(subject, id, 0, {
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

/** The subject's recovery-code sets among `records`. */
const setsAmong = (records: readonly MfaFactorRecord[]): MfaFactorRecord[] =>
	records.filter((record) => record.kind === RECOVERY_CODE_FACTOR_KIND);

/** The subject's sets as listed now, or why they could not be. */
async function setsOf(
	factorStore: MfaFactorSetWrites["factorStore"],
	subject: string,
): Promise<{ readonly records: readonly MfaFactorRecord[] } | { readonly cause: unknown }> {
	try {
		const records: unknown = await factorStore.list(subject);
		if (!Array.isArray(records)) {
			throw new TypeError("MfaFactorStore.list answered something that is not a list");
		}
		return { records: setsAmong(records as MfaFactorRecord[]) };
	} catch (cause) {
		return { cause };
	}
}

/** Each of `ids` removed: `undefined` once all are, else the first failure. */
async function removeEach(
	factorStore: MfaFactorSetWrites["factorStore"],
	subject: string,
	ids: readonly string[],
): Promise<{ readonly cause: unknown } | undefined> {
	let failed: { readonly cause: unknown } | undefined;
	for (const id of ids) {
		try {
			await factorStore.remove(subject, id);
		} catch (cause) {
			failed ??= { cause };
		}
	}
	return failed;
}
