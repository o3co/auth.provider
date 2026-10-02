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
 * again: a key of its own in the store's `w:` namespace, outside every
 * session's `${prefix}${sid}:*` (the pattern `removeBySid`'s migration scan
 * sweeps, so a logout never removes an answer before it expires), on its
 * record's Redis Cluster slot, so the write's script touches one slot.
 */

/**
 * The part of `key` Redis Cluster hashes: its first `{…}` holding at least one
 * character, else the whole key.
 */
const hashedPartOf = (key: string): string => {
	const open = key.indexOf("{");
	if (open !== -1) {
		const close = key.indexOf("}", open + 1);
		if (close > open + 1) return key.slice(open + 1, close);
	}
	return key;
};

/**
 * The replay key of the write `writeId` to `key`, a key under `prefix`:
 * `<prefix>w:{<tag>}:<writeId>`, where `<tag>` is the part of `key` Redis
 * hashes, so it hashes as `key` does. `null` when no such key hashes as `key`
 * does: a key whose braces leave it no tag (a `}` with no `{` before it, or an
 * empty `{}`) is hashed whole, and `{<key>}` would end at its first `}`.
 */
export function replayKeyOf(key: string, prefix: string, writeId: string): string | null {
	const hashed = hashedPartOf(key);
	const replayKey = `${prefix}w:{${hashed}}:${writeId}`;
	return hashedPartOf(replayKey) === hashed ? replayKey : null;
}
