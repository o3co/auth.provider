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
 * What a Redis server says about keeping what it is written, for the boot checks of the MFA
 * stores and the attempt counter. A reply that refuses a question leaves that part unread; any
 * other failure rejects.
 */

import type { Redis } from "ioredis";
import type { RedisDurability } from "../clients.mjs";

/**
 * A reply that refuses the question — an unknown or renamed command, an
 * unknown subcommand, `NOPERM`, a command a managed service disabled — rather
 * than one that says the server cannot answer now (`BUSY`, `LOADING`,
 * `NOAUTH`, `READONLY`, anything else), which fails the boot as any store
 * outage at boot does.
 */
const REFUSED_QUESTION =
	/^(?:NOPERM\b|ERR unknown command\b|ERR unknown subcommand\b|ERR\b.*\b(?:disabled|not allowed|not permitted|not supported|not available)\b)/i;

const isRefusal = (err: unknown): boolean =>
	err instanceof Error && err.name === "ReplyError" && REFUSED_QUESTION.test(err.message);

/**
 * `CONFIG GET <name>`'s value: the reply is `[name, value]`, or empty for a name the server
 * does not know.
 */
const configValue = (reply: unknown, name: string): string | undefined =>
	Array.isArray(reply) && reply[0] === name && typeof reply[1] === "string" ? reply[1] : undefined;

/** An `INFO` section's `<name>:<value>` line's value. */
const infoValue = (section: unknown, name: string): string | undefined =>
	typeof section === "string"
		? new RegExp(`^${name}:([^\\r\\n]*)`, "m").exec(section)?.[1]
		: undefined;

/**
 * What `io`'s server says about keeping what it is written. The policy from `INFO memory`
 * (`CONFIG GET maxmemory-policy` only where INFO does not say, so a managed server that blocks
 * `CONFIG` still reports it); AOF from `INFO persistence`; `CONFIG GET save` only when AOF is
 * off, to tell RDB snapshots from none. A refused question leaves its part unread; any other
 * failure is the caller's.
 */
export async function redisDurability(io: Redis): Promise<RedisDurability> {
	let refusal: unknown;
	const ask = async (question: () => Promise<unknown>): Promise<unknown> => {
		try {
			return await question();
		} catch (err) {
			if (!isRefusal(err)) throw err;
			refusal ??= err;
			return undefined;
		}
	};
	const maxmemoryPolicy =
		infoValue(await ask(() => io.info("memory")), "maxmemory_policy") ??
		configValue(await ask(() => io.config("GET", "maxmemory-policy")), "maxmemory-policy");
	const aof = infoValue(await ask(() => io.info("persistence")), "aof_enabled");
	const appendOnly = aof === "1" ? true : aof === "0" ? false : undefined;
	let snapshots: boolean | undefined;
	if (appendOnly === false) {
		const save = configValue(await ask(() => io.config("GET", "save")), "save");
		snapshots = save === undefined ? undefined : save.trim() !== "";
	}
	return { maxmemoryPolicy, appendOnly, snapshots, refusal };
}
