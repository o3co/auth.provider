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
 * What a Redis server says about keeping what it is written — read at boot
 * by a store module whose keys must outlive memory pressure and a restart.
 * Each part is `undefined` when it could not be read: the server refused the
 * question (`refusal`), or answered without the value.
 */
export interface RedisDurability {
	/** `INFO memory`'s `maxmemory_policy`, or `CONFIG GET maxmemory-policy` where INFO does not say. */
	readonly maxmemoryPolicy: string | undefined;
	/** `INFO persistence`'s `aof_enabled`. */
	readonly appendOnly: boolean | undefined;
	/** `CONFIG GET save` is not empty: RDB snapshots are taken. Asked only when AOF is off. */
	readonly snapshots: boolean | undefined;
	/** The first reply that refused a question — an unknown or renamed command, `NOPERM`, a disabled command — as the driver raised it. Logged by its projection only. */
	readonly refusal: unknown;
}
