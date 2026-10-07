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
 * What `MfaFactorStore.list` answered, read as a list of records: the one
 * reading every read of the list in this package goes through, but the
 * operator reset's snapshot of what it removes (`factorSet.mts`), which only
 * counts for its report and reads the list as listed.
 *
 * The answer must be an array, every entry an own element that is an object
 * with a string `kind` — the field every judgment over the records keys on.
 * Anything else throws — a `TypeError`, or what reading an entry's `kind`
 * threw — the store's fault, which each caller answers as the store's
 * outage: a hole or an entry that is not a record would otherwise be
 * skipped, or read as a kind it is not, and the subject read as holding
 * fewer factors than the store holds. An empty list is a subject with none.
 * The rest of a record's fields are read where they are used.
 */

import type { MfaFactorRecord } from "@o3co/auth-provider-core";

/** `answer` as a fresh array of the records it holds; throws for anything but a list of records. */
export function readFactorList(answer: unknown): MfaFactorRecord[] {
	if (!Array.isArray(answer)) {
		throw new TypeError("MfaFactorStore.list answered something that is not a list");
	}
	const records: MfaFactorRecord[] = [];
	for (let index = 0; index < answer.length; index++) {
		const entry: unknown = Object.hasOwn(answer, index) ? answer[index] : undefined;
		if (
			typeof entry !== "object" ||
			entry === null ||
			typeof (entry as { readonly kind?: unknown }).kind !== "string"
		) {
			throw new TypeError("MfaFactorStore.list answered a list with an entry that is not a record");
		}
		records.push(entry as MfaFactorRecord);
	}
	return records;
}
