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
 * When a previous key stops verifying: the one rule the keystores apply to a
 * previous key's `expiresAt`.
 *
 * A keystore reads each date once, when it is built, as epoch milliseconds,
 * and refuses one that is not a Date holding a valid time: an Invalid Date
 * compares false both ways, so it would read as a key never retired. Holding
 * the number, not the caller's Date object, keeps the deadline where it was
 * configured whatever the caller does with that object afterwards. A key
 * verifies only strictly before its time, and a time that cannot be compared
 * counts as passed.
 */

/** The time a Date holds (NaN for an Invalid Date), or `undefined` for anything that is not a Date. */
function timeOf(value: unknown): number | undefined {
	try {
		// Reads the Date's own time slot: a Date from another realm reads as
		// one, and an object merely shaped like a Date is not one.
		return Date.prototype.getTime.call(value as Date);
	} catch {
		return undefined;
	}
}

/**
 * Reads each previous key's retirement date as epoch milliseconds, refusing
 * one that is not a Date holding a valid time. `dates` names each by where it
 * was configured (`previousKeys[0].expiresAt`); the message names that place
 * and what is wrong, never the value.
 */
export function readRetirementTimes(
	owner: string,
	dates: ReadonlyArray<readonly [where: string, expiresAt: unknown]>,
): number[] {
	return dates.map(([where, expiresAt]) => {
		const time = timeOf(expiresAt);
		if (time === undefined || !Number.isFinite(time)) {
			const what =
				time !== undefined
					? "an invalid Date"
					: expiresAt === null
						? "null"
						: `not a Date (${typeof expiresAt})`;
			throw new Error(
				`${owner}: ${where} is not a usable retirement date (${what}). ` +
					"A previous key verifies until its expiresAt and never after, so expiresAt must be " +
					"a Date holding a valid time.",
			);
		}
		return time;
	});
}

/**
 * Whether a key retiring at `retiresAt` still verifies at `now`, both epoch
 * milliseconds: only strictly before it. A time that cannot be compared
 * counts as passed.
 */
export const verifiesBefore = (retiresAt: number, now: number): boolean => now < retiresAt;
