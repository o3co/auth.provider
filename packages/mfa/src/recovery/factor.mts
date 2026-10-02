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
 * The `recovery_code` factor (the MFA ADR's D22, D25) and the set it issues.
 *
 * - It does not count, adds `recovery` and `mfa`, is not guessable, and is
 *   never enrolled on its own: a set is issued beside a first counting
 *   factor (`generateRecoveryCodes`), one record per set.
 * - A set is `count` long codes, answered once in groups; the record keeps
 *   only a keyed digest of each code, each naming its key, under the kind's
 *   digests — never a code — with the set's generation and whether its codes
 *   were answered (`shown`, false until then). A set written before either
 *   was kept reads as generation 0, shown.
 * - A verification reads the proof as typed and compares it with every
 *   digest of the set; a match answers the set without that digest, the rest
 *   of its data as it was, which the coordinator writes by compare-and-set,
 *   so a code is spent once. A digest whose key left the ring throws: an
 *   outage, never a code refused. A set with no code left is kept, and
 *   refuses every code.
 * - The one rule a set is held to before its verification
 *   (`recoverySetRefusal`): one below the subject's recovery-set floor is
 *   retired, and one whose digest needs a key the ring no longer holds names
 *   that key.
 */

import {
	type MfaDigests,
	type MfaFactor,
	type MfaFactorData,
	type MfaKeyedDigest,
	type MfaVerification,
	type MfaVerifyContext,
	RECOVERY_CODE_AMR,
} from "@o3co/auth-provider-core";
import { formatLongCode, generateLongCode, readLongCode } from "../codes.mjs";

/** The kind a recovery-code set's record carries, and the key the factor is contributed under. */
export const RECOVERY_CODE_FACTOR_KIND = "recovery_code";

/** What the factor issues: how many codes a set holds. */
export interface RecoveryCodeFactorSettings {
	readonly count: number;
}

/** A set as issued: the codes to answer once, shown in groups, and the record's data, their digests. */
export interface RecoveryCodeSet {
	readonly codes: readonly string[];
	readonly data: MfaFactorData;
}

const AMR: readonly string[] = Object.freeze([RECOVERY_CODE_AMR]);

/** The settings of each factor this file made: another object under the kind issues nothing. */
const issuers = new WeakMap<object, RecoveryCodeFactorSettings>();

const notEnrolled = async (): Promise<never> => {
	throw new RangeError("recovery codes are issued beside a counting factor, never enrolled");
};

/** A set as its data holds it. */
interface RecoverySet {
	readonly codes: readonly MfaKeyedDigest[];
	readonly generation: number;
	readonly shown: boolean;
}

/**
 * The set `data` holds, each field read once; `undefined` for data that is
 * not a set — codes that are not keyed digests, a generation that is not a
 * safe whole number, a `shown` that is not a boolean. One written before
 * either was kept is generation 0, shown.
 */
const setIn = (data: MfaFactorData): RecoverySet | undefined => {
	const { codes, generation, shown } = data;
	if (!Array.isArray(codes)) return undefined;
	const kept = codes.filter(
		(entry): entry is MfaKeyedDigest =>
			typeof entry === "object" &&
			entry !== null &&
			typeof (entry as MfaKeyedDigest).keyId === "string" &&
			typeof (entry as MfaKeyedDigest).digest === "string",
	);
	if (kept.length !== codes.length) return undefined;
	if (
		generation !== undefined &&
		!(Number.isSafeInteger(generation) && (generation as number) >= 0)
	) {
		return undefined;
	}
	if (shown !== undefined && typeof shown !== "boolean") return undefined;
	return { codes: kept, generation: (generation as number | undefined) ?? 0, shown: shown ?? true };
};

/** The digests a set's data holds; `undefined` for data that is not a set. */
const digestsIn = (data: MfaFactorData): readonly MfaKeyedDigest[] | undefined =>
	setIn(data)?.codes;

/**
 * `proof` checked against the set `data` holds, under `digests`: every
 * digest compared, so the time taken does not say which one matched. A
 * match answers the set without it.
 */
function spendRecoveryCode(
	digests: MfaDigests,
	factorId: string,
	data: MfaFactorData,
	proof: unknown,
): MfaVerification {
	const kept = digestsIn(data);
	if (kept === undefined) throw new TypeError("a recovery-code set's data is not a set of digests");
	const code = readLongCode(proof);
	if (code === undefined) return { ok: false, reason: "malformed" };
	const found = kept.map((stored) => digests.matchesDigest([code], stored));
	if (found.includes("key_unavailable")) {
		throw new RangeError("a recovery code's digest names a key the ring no longer holds");
	}
	const matched = found.indexOf("match");
	if (matched === -1) return { ok: false, reason: "invalid" };
	return {
		ok: true,
		factorId,
		next: { ...data, codes: kept.filter((_, index) => index !== matched) },
	};
}

/** The `recovery_code` factor, issuing sets of `settings.count` codes. */
export function createRecoveryCodeFactor(settings: RecoveryCodeFactorSettings): MfaFactor {
	const factor: MfaFactor = Object.freeze({
		kind: RECOVERY_CODE_FACTOR_KIND,
		amrValues: AMR,
		amrFor: () => AMR,
		addsMfa: true,
		counting: false,
		guessable: false,
		describe: () => ({}),
		enrollable: () => false,
		verify: async (ctx: MfaVerifyContext) =>
			spendRecoveryCode(ctx.digests, ctx.factor.id, ctx.factor.data, ctx.proof),
		beginEnrollment: notEnrolled,
		completeEnrollment: notEnrolled,
	});
	issuers.set(factor, { count: settings.count });
	return factor;
}

/**
 * A new set of `generation` from `factor`, not yet shown, its codes digested
 * under `digests` (the kind's, under the ring's first key); `undefined` for a
 * factor this file did not make.
 */
export function generateRecoveryCodes(
	factor: MfaFactor,
	digests: MfaDigests,
	generation = 0,
): RecoveryCodeSet | undefined {
	const settings = issuers.get(factor);
	if (settings === undefined) return undefined;
	const made = new Set<string>();
	while (made.size < settings.count) made.add(generateLongCode());
	const codes = [...made];
	return {
		codes: codes.map(formatLongCode),
		data: { codes: codes.map((code) => digests.digest([code])), generation, shown: false },
	};
}

/** The generation of the set `data` holds, for a factor this file made; `undefined` otherwise, or for data that is not a set. */
export function recoverySetGeneration(factor: MfaFactor, data: MfaFactorData): number | undefined {
	return issuers.has(factor) ? setIn(data)?.generation : undefined;
}

/** Whether the set `data` holds was answered, for a factor this file made; `undefined` otherwise, or for data that is not a set. */
export function recoverySetShown(factor: MfaFactor, data: MfaFactorData): boolean | undefined {
	return issuers.has(factor) ? setIn(data)?.shown : undefined;
}

/** The set `data` holds, marked answered; `undefined` for data that is not a set. */
export function shownRecoverySet(data: MfaFactorData): MfaFactorData | undefined {
	return setIn(data) === undefined ? undefined : { ...data, shown: true };
}

/** Why a verification is not handed a set: retired below the floor, or a digest under a key the ring lost. */
export type RecoverySetRefusal =
	| { readonly reason: "retired" }
	| { readonly reason: "key_unavailable"; readonly keyId: string };

/**
 * Why the set `data` holds is not verified, for a factor this file made:
 * below `floor`, the subject's recovery-set floor, it is retired; a digest
 * whose key `holdsKey` denies names that key. `undefined` for anything else —
 * another factor, a set the rule passes, or data that is not a set, which
 * the verification answers.
 */
export function recoverySetRefusal(
	factor: MfaFactor,
	data: MfaFactorData,
	context: { readonly floor: number; readonly holdsKey: (keyId: string) => boolean },
): RecoverySetRefusal | undefined {
	if (!issuers.has(factor)) return undefined;
	const set = setIn(data);
	if (set === undefined) return undefined;
	if (set.generation < context.floor) return { reason: "retired" };
	const missing = set.codes.find((stored) => !context.holdsKey(stored.keyId));
	return missing === undefined ? undefined : { reason: "key_unavailable", keyId: missing.keyId };
}

/** Whether `factor` is one this file made: a recovery-code factor whose sets this file reads. */
export const isRecoveryCodeFactor = (factor: MfaFactor): boolean => issuers.has(factor);

/** The key ids the set `data`'s digests name, for a factor this file made; `undefined` otherwise, or for data that is not a set. */
export function recoverySetKeyIds(factor: MfaFactor, data: MfaFactorData): string[] | undefined {
	if (!issuers.has(factor)) return undefined;
	return digestsIn(data)?.map((stored) => stored.keyId);
}

/** Whether `data` is a set with no code left, for a factor this file made; data that is not a set is not one. */
export function isExhaustedRecoverySet(factor: MfaFactor, data: MfaFactorData): boolean {
	return issuers.has(factor) && digestsIn(data)?.length === 0;
}

/**
 * How many codes the set `data` holds, for a factor this file made; none
 * for data that is not a set; `undefined` for any other factor.
 */
export function recoveryCodesLeft(factor: MfaFactor, data: MfaFactorData): number | undefined {
	if (!issuers.has(factor)) return undefined;
	return digestsIn(data)?.length ?? 0;
}
