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
 * Where a conditional write keeps its answer for a copy the driver sends
 * again: a key of its own, under the store's prefix, on its record's Redis
 * Cluster slot, so the write's script touches one slot.
 */

/** Whether `key` carries a Redis Cluster hash tag: a `{`, then a `}` after at least one character. */
const hasHashTag = (key: string): boolean => {
	const open = key.indexOf("{");
	return open !== -1 && key.indexOf("}", open + 1) > open + 1;
};

/**
 * The replay key of the write `writeId` to `key`, a key under `prefix`.
 * `<key>:w:<writeId>` when `key` carries a hash tag, which the suffix keeps;
 * otherwise `<prefix>w:{<key>}:<writeId>`, whose tag is the whole of `key`, so
 * it hashes as `key` does. A key holding a `}` but no tag can share no slot by
 * either form, and is given the first: one Redis node serves it, a Cluster
 * refuses the script.
 */
export function replayKeyOf(key: string, prefix: string, writeId: string): string {
	if (hasHashTag(key) || key.includes("}")) return `${key}:w:${writeId}`;
	return `${prefix}w:{${key}}:${writeId}`;
}
