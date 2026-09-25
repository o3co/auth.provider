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
 * How a typed answer carries what the route that logs it needs and the caller
 * must not see — the failure it was turned from (`failure`), the store errors
 * it does not stand for (`absorbed`), the connection a refusal is about
 * (`connection`) — as a property nothing enumerates. A spread, a
 * serialisation, or a response or audit event built from the answer never
 * carries what a store or an upstream put on an error; a reader that asks for
 * the field by name gets it. Used by the retrieval and by lodging.
 */

/** `value`, with `payload` attached under `key` and not enumerable; nothing is attached for none. */
export function carrying<T extends object>(
	value: T,
	key: "failure" | "absorbed" | "connection",
	payload: unknown,
): T {
	if (payload !== undefined) {
		Object.defineProperty(value, key, { value: payload, enumerable: false });
	}
	return value;
}

/** `value`, carrying the failure it was turned from. */
export const carryingFailure = <T extends object>(value: T, failure: unknown): T =>
	carrying(value, "failure", failure);
