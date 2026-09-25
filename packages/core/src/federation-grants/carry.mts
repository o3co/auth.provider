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
 * How a typed answer carries the failure it was turned from (`failure`) to
 * the route that logs it: as a property nothing enumerates. A spread, a
 * serialisation, or a response or audit event built from the answer never
 * carries what a store or an upstream put on the error; a reader that asks
 * for `failure` by name gets it. Used by the retrieval and by lodging.
 */

/** `value`, with `failure` attached and not enumerable; nothing is attached for no failure. */
export function carryingFailure<T extends object>(value: T, failure: unknown): T {
	if (failure !== undefined) {
		Object.defineProperty(value, "failure", { value: failure, enumerable: false });
	}
	return value;
}
