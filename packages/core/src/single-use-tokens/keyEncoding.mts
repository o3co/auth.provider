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
 * Combine `scope` and `key` into a single storage key with length-prefix
 * encoding. The length prefix neutralises any delimiter collision because
 * the parser would always need the prefix to decide where each segment ends.
 *
 * Both adapters (memory, redis) MUST use this same encoding so a key written
 * by one is readable by the other (relevant in tests that swap adapters).
 *
 * `String.prototype.length` (UTF-16 code units) is used because the value
 * just needs to be self-consistent within one adapter instance — not match
 * any external Unicode definition.
 */
export function canonicalKey(scope: string, key: string): string {
	return `${scope.length}:${scope}|${key.length}:${key}`;
}
