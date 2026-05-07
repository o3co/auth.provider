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
 * RFC 6749 §5.2 error response envelope. Used across `/oauth/*` and the
 * session router so consumer code can parse error responses with a single
 * shape regardless of which surface produced them.
 */
export interface ErrorEnvelope {
	readonly error: string;
	readonly error_description?: string;
	readonly error_uri?: string;
}

/**
 * Construct an RFC 6749 §5.2 error envelope. Optional fields are omitted
 * (rather than serialized as `undefined`) so JSON consumers see a clean
 * shape — `JSON.stringify({ x: undefined })` does drop the key, but having
 * the helper pre-omit keeps the in-memory object consistent for tests
 * that snapshot the structure with `toEqual`.
 *
 * @param error       Machine-readable error code (snake_case, e.g. `invalid_grant`).
 * @param description Optional human-readable detail.
 * @param uri         Optional reference URL.
 */
export function errorEnvelope(error: string, description?: string, uri?: string): ErrorEnvelope {
	return {
		error,
		...(description !== undefined ? { error_description: description } : {}),
		...(uri !== undefined ? { error_uri: uri } : {}),
	};
}
