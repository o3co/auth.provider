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
 * What a session's `enrollmentFacts` may hold, read one way by both bundled
 * stores and by session admission: a witness `MfaEnrollmentWitness` admits
 * and a boolean, copied to those two fields and nothing else, so no address
 * or other part of a `User` is ever kept or handed on through them.
 */

import type { MfaEnrollmentWitness } from "../repositories/UserRepository.mjs";
import type { SessionEnrollmentFacts } from "./types.mjs";

/** Every value `MfaEnrollmentWitness` admits: `satisfies` fails the build when the type gains or loses one. */
const WITNESSES = {
	enrolled: true,
	not_enrolled: true,
	malformed: true,
} as const satisfies Record<MfaEnrollmentWitness, true>;

/**
 * `value` as `SessionEnrollmentFacts`: a new object holding its two fields
 * when it is one, else `undefined`. Each field is read once; a read that
 * throws is no value.
 */
export function readEnrollmentFacts(value: unknown): SessionEnrollmentFacts | undefined {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
	try {
		const { witness, mailAddress } = value as Record<string, unknown>;
		return typeof witness === "string" &&
			Object.hasOwn(WITNESSES, witness) &&
			typeof mailAddress === "boolean"
			? { witness: witness as MfaEnrollmentWitness, mailAddress }
			: undefined;
	} catch {
		return undefined;
	}
}

/**
 * What a store records as a session's `enrollmentFacts`: `undefined` for
 * none, else a copy of the two facts. Every bundled store's `create` records
 * this answer, never its own input, so both refuse the same values.
 *
 * @throws RangeError naming the session, quoting nothing of the value, for
 *   anything else.
 */
export function recordableEnrollmentFacts(
	sid: string,
	value: unknown,
): SessionEnrollmentFacts | undefined {
	if (value === undefined) return undefined;
	const facts = readEnrollmentFacts(value);
	if (facts === undefined) {
		throw new RangeError(
			`UserSession ${sid}: enrollmentFacts must be a witness ("enrolled", "not_enrolled" or "malformed") and a boolean mailAddress, or undefined`,
		);
	}
	return facts;
}
