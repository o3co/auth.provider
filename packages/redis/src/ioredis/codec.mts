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
 * The values the wrappers exchange with the scripts: a number as a Redis argument, and a reply
 * as the client contract's fields. A reply of any other shape reads as no fields or no value;
 * none of these throws.
 */

import type { DeviceCodeRecordFields, FederationGrantHashFields } from "../clients.mjs";

/**
 * `HGETALL`'s flat `[field, value, …]` reply — as a script returns it — as
 * the hash's fields. Anything but a list is no fields. The one reading of
 * that reply, shared by every store here that has a script answer a hash.
 */
export const hashFields = (flat: unknown): Record<string, string> => {
	const pairs = Array.isArray(flat) ? (flat as string[]) : [];
	const fields: Record<string, string> = {};
	for (let i = 0; i + 1 < pairs.length; i += 2) {
		fields[pairs[i] as string] = pairs[i + 1] as string;
	}
	return fields;
};

/** `HGETALL`'s flat `[field, value, …]` reply as the record's fields. */
export const deviceCodeRecordOf = (flat: unknown): DeviceCodeRecordFields =>
	hashFields(flat) as unknown as DeviceCodeRecordFields;

/** A number as a Redis argument: never in exponent form, whatever its magnitude. */
export const fgNumber = (value: number): string =>
	Number.isFinite(value) ? value.toFixed(0) : String(value);

/** `HGETALL`'s flat `[field, value, …]` reply as the record's fields. */
export const fgFields = (flat: unknown): FederationGrantHashFields =>
	hashFields(flat) as unknown as FederationGrantHashFields;

/**
 * A write's reply: `[1, fields]` when it happened, `[0]` when it was refused.
 * Absence and a failed precondition are the same answer on purpose: the
 * record may change again before the caller looks, so the port re-reads.
 */
export const fgWritten = (reply: unknown): FederationGrantHashFields | null => {
	if (!Array.isArray(reply) || reply[0] !== 1) return null;
	return fgFields(reply[1]);
};

export const fgiText = (reply: unknown): string | null =>
	typeof reply === "string" ? reply : null;
