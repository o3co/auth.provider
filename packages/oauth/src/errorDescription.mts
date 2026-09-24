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
 * Holds an `error_description` to the characters RFC 6749 allows in one.
 *
 * RFC 6749 §5.2 (the token endpoint) and §4.1.2.1 (the authorization
 * endpoint's error redirect) both define `error_description` as
 * `%x20-21 / %x23-5B / %x5D-7E`: printable ASCII without `"` and `\`.
 * Descriptions are written by many hands — every grant a composition
 * installs, and the routes themselves — and several quote what the client
 * sent (a grant type, a scope, an audience, a token type, a
 * `response_type`), so the routes apply this where they write the field
 * rather than trusting each author to escape. Descriptions quote a value
 * with `'`, which the set allows.
 */

/** Everything outside `%x20-21 / %x23-5B / %x5D-7E`, one code point at a time. */
const OUTSIDE_ERROR_DESCRIPTION_SET = /[^\x20-\x21\x23-\x5B\x5D-\x7E]/gu;

/** `description` with every character RFC 6749 does not allow replaced by `?`. */
export function sanitizeErrorDescription(description: string): string {
	return description.replace(OUTSIDE_ERROR_DESCRIPTION_SET, "?");
}
