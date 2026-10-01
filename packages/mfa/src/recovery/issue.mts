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
 * Replacing — a first counting factor bound over a standing set — writes the
 * new set first, then removes the subject's other `recovery_code` records. A
 * removal or a listing that fails leaves the old set usable beside the new
 * one, answered with why; it never undoes the new set.
 */

import { randomBytes } from "node:crypto";
import type { MfaFactorRecord, MfaFactorResolver, MfaFactorStore } from "@o3co/auth-provider-core";
import type { MfaSealing } from "../sealing.mjs";
import { generateRecoveryCodes, RECOVERY_CODE_FACTOR_KIND } from "./factor.mjs";

/**
 * What issuing came to: nothing while the factor is off, the codes to answer
 * once, or not issued, with why. Asked to replace, it also says whether the
 * new set replaces one — another stood, or could not be ruled out — and why
 * one may still stand (`unreplaced`).
 */
export type MfaIssuedRecoveryCodes =
	| {
			readonly issued: true;
			readonly codes: readonly string[];
			readonly regenerated?: boolean;
			readonly unreplaced?: unknown;
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
	/** Whether the subject's other sets are removed once the new one is written. */
	readonly replace?: boolean;
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
		if (options.replace !== true) return { issued: true, codes: set.codes };
		return { issued: true, codes: set.codes, ...(await removeOthers(factorStore, subject, id)) };
	} catch (cause) {
		return { issued: false, cause };
	}
}

/** The subject's `recovery_code` records other than `kept` removed: whether any stood, and why one may still stand. */
async function removeOthers(
	factorStore: MfaFactorStore,
	subject: string,
	kept: string,
): Promise<{ readonly regenerated: boolean; readonly unreplaced?: unknown }> {
	let others: readonly MfaFactorRecord[];
	try {
		others = (await factorStore.list(subject)).filter(
			(record) => record.kind === RECOVERY_CODE_FACTOR_KIND && record.id !== kept,
		);
	} catch (cause) {
		return { regenerated: true, unreplaced: cause };
	}
	let unreplaced: { readonly cause: unknown } | undefined;
	for (const record of others) {
		try {
			await factorStore.remove(subject, record.id);
		} catch (cause) {
			unreplaced ??= { cause };
		}
	}
	return {
		regenerated: others.length > 0,
		...(unreplaced === undefined ? {} : { unreplaced: unreplaced.cause }),
	};
}
