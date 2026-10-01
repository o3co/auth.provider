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
 * sealed to it, as the binding it follows authorized it. Never throws: a set
 * that cannot be made or written is answered not issued, with why, so what
 * it follows stands.
 *
 * The new set replaces the subject's sets that stood before it: they are
 * listed first, the new one is written, then those — and only those — are
 * removed, so a set written after the listing (another binding's) is never
 * removed. A listing or a removal that fails leaves an old set usable beside
 * the new one, answered with why; it never undoes the new set. Asked to keep
 * them (`keep`, with why), it removes none.
 */

import { randomBytes } from "node:crypto";
import type { MfaFactorRecord, MfaFactorResolver, MfaFactorStore } from "@o3co/auth-provider-core";
import type { MfaSealing } from "../sealing.mjs";
import { generateRecoveryCodes, RECOVERY_CODE_FACTOR_KIND } from "./factor.mjs";

/** Why a set that stood may still stand beside the new one: kept as asked, or a listing or removal that failed. */
export type MfaUnreplacedRecoveryCodes =
	| { readonly kept: "password_binding" }
	| { readonly cause: unknown };

/**
 * What issuing came to: nothing while the factor is off, or not issued, with
 * why; or the codes to answer once, whether the new set replaces one —
 * `regenerated`: one stood, or could not be ruled out — and why one may
 * still stand (`unreplaced`).
 */
export type MfaIssuedRecoveryCodes =
	| {
			readonly issued: true;
			readonly codes: readonly string[];
			readonly regenerated: boolean;
			readonly unreplaced?: MfaUnreplacedRecoveryCodes;
	  }
	| { readonly issued: false; readonly cause: unknown }
	| undefined;

export interface IssueRecoveryCodesOptions {
	readonly factors: MfaFactorResolver;
	readonly factorStore: MfaFactorStore;
	readonly sealing: MfaSealing;
	readonly subject: string;
	/** What authorized the binding the set is issued beside. */
	readonly binding: NonNullable<MfaFactorRecord["binding"]>;
	readonly nowMs: number;
	/** Keep the sets that stood, and why: a reopened login's first binding by `password`. */
	readonly keep?: "password_binding";
}

/** A new set for `options.subject` (see this file's header). */
export async function issueRecoveryCodes(
	options: IssueRecoveryCodesOptions,
): Promise<MfaIssuedRecoveryCodes> {
	const { factors, factorStore, sealing, subject } = options;
	const factor = factors.get(RECOVERY_CODE_FACTOR_KIND);
	if (factor === undefined) return undefined;
	try {
		const set = generateRecoveryCodes(factor, sealing.digestsFor(RECOVERY_CODE_FACTOR_KIND));
		if (set === undefined) return undefined;
		const standing = await setsOf(factorStore, subject);
		const id = randomBytes(16).toString("base64url");
		await factorStore.create({
			id,
			subject,
			kind: RECOVERY_CODE_FACTOR_KIND,
			label: undefined,
			binding: options.binding,
			createdAt: new Date(options.nowMs),
			lastUsedAt: undefined,
			version: 0,
			data: sealing.sealFactorData({ subject, id, kind: RECOVERY_CODE_FACTOR_KIND }, set.data),
		});
		const issued = { issued: true as const, codes: set.codes };
		if ("cause" in standing) return { ...issued, regenerated: true, unreplaced: standing };
		if (standing.ids.length === 0) return { ...issued, regenerated: false };
		if (options.keep !== undefined) {
			return { ...issued, regenerated: true, unreplaced: { kept: options.keep } };
		}
		const failed = await removeEach(factorStore, subject, standing.ids);
		return {
			...issued,
			regenerated: true,
			...(failed === undefined ? {} : { unreplaced: failed }),
		};
	} catch (cause) {
		return { issued: false, cause };
	}
}

/** The ids of the subject's sets as listed now, or why they could not be. */
async function setsOf(
	factorStore: MfaFactorStore,
	subject: string,
): Promise<{ readonly ids: readonly string[] } | { readonly cause: unknown }> {
	try {
		const records: unknown = await factorStore.list(subject);
		if (!Array.isArray(records)) {
			throw new TypeError("MfaFactorStore.list answered something that is not a list");
		}
		return {
			ids: (records as MfaFactorRecord[])
				.filter((record) => record.kind === RECOVERY_CODE_FACTOR_KIND)
				.map((record) => record.id),
		};
	} catch (cause) {
		return { cause };
	}
}

/** Each of `ids` removed: `undefined` once all are, else the first failure. */
async function removeEach(
	factorStore: MfaFactorStore,
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
