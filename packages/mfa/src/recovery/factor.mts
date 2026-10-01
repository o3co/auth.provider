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
 *   digests — never a code.
 * - Its verification is not built: `verify` throws, which the coordinator
 *   answers `503`, never a code accepted or refused.
 */

import {
	type MfaDigests,
	type MfaFactor,
	type MfaFactorData,
	RECOVERY_CODE_AMR,
} from "@o3co/auth-provider-core";
import { formatLongCode, generateLongCode } from "../codes.mjs";

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
		verify: async (): Promise<never> => {
			throw new Error("this build does not verify recovery codes");
		},
		beginEnrollment: notEnrolled,
		completeEnrollment: notEnrolled,
	});
	issuers.set(factor, { count: settings.count });
	return factor;
}

/**
 * A new set from `factor`, its codes digested under `digests` (the kind's,
 * under the ring's first key); `undefined` for a factor this file did not
 * make.
 */
export function generateRecoveryCodes(
	factor: MfaFactor,
	digests: MfaDigests,
): RecoveryCodeSet | undefined {
	const settings = issuers.get(factor);
	if (settings === undefined) return undefined;
	const made = new Set<string>();
	while (made.size < settings.count) made.add(generateLongCode());
	const codes = [...made];
	return {
		codes: codes.map(formatLongCode),
		data: { codes: codes.map((code) => digests.digest([code])) },
	};
}
