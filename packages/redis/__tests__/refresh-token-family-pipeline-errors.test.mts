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

// `updateFamily`'s CAS reads its `EXEC` reply for `null` (the WATCH abort),
// and the ioredis wrapper's `exec()` reads it for per-command errors: ioredis
// reports a failed queued command inside the reply and resolves, since `EXEC`
// itself succeeded. Unchecked, a `SET` Redis refused (OOM, a read-only
// replica, a `maxmemory-policy` eviction refusal) passes the `null` check as
// `{ outcome: "committed" }` for a rotation that never landed: the caller
// issues a refresh token while Redis still holds the old `activeJti`, and the
// token's next use reads as replay, revoking the family and logging the user
// out.
//
// The real store runs through the real wrapper with only the driver faked, so
// removing the reply check in `ioredis/commands.mts` fails these tests.

import type { RefreshTokenFamily } from "@o3co/auth-provider-core";
import type { Redis } from "ioredis";
import { describe, expect, it, vi } from "vitest";
import { makeIoredisClients } from "#/ioredis.mjs";
import { createRedisRefreshTokenFamilyStore } from "#/refresh-token-family.mjs";

const FAMILY: RefreshTokenFamily = Object.freeze({
	familyId: "fam-1",
	activeJti: "jti-old",
	revoked: false,
	expiresAtMs: Date.now() + 3600_000,
});

/**
 * A fake ioredis whose `EXEC` replies are scripted per call. `duplicate()`
 * returns the same object — the store opens one isolated connection per
 * `updateFamily`, and reusing it keeps the scripted replies observable.
 */
function makeFakeIoredis(execReplies: unknown[]) {
	const queued: unknown[][] = [];
	let call = 0;
	const io: Record<string, unknown> = {
		get: vi.fn(async () => JSON.stringify(FAMILY)),
		pttl: vi.fn(async () => 3600_000),
		watch: vi.fn(async () => "OK"),
		unwatch: vi.fn(async () => "OK"),
		set: vi.fn(async () => "OK"),
		// A server that does not evict, as the store's eviction gate reads it.
		info: vi.fn(async (section: string) =>
			section === "memory"
				? "# Memory\r\nmaxmemory_policy:noeviction\r\n"
				: "# Persistence\r\naof_enabled:1\r\n",
		),
		on: vi.fn(),
		quit: vi.fn(async () => "OK"),
		disconnect: vi.fn(),
		connect: vi.fn(async () => undefined),
		multi: vi.fn(() => {
			const commands: unknown[] = [];
			queued.push(commands);
			const pipeline: Record<string, unknown> = {
				exec: vi.fn(async () => execReplies[Math.min(call++, execReplies.length - 1)]),
			};
			for (const cmd of ["set", "pexpire", "pexpireat", "hset", "zadd", "sadd"]) {
				pipeline[cmd] = vi.fn((...args: unknown[]) => {
					commands.push([cmd, ...args]);
					return pipeline;
				});
			}
			return pipeline;
		}),
	};
	io.duplicate = vi.fn(() => io);
	return { io: io as unknown as Redis, queued };
}

const makeStore = async (execReplies: unknown[]) => {
	const { io, queued } = makeFakeIoredis(execReplies);
	const { refreshTokenFamilyClient } = makeIoredisClients(io);
	return {
		queued,
		store: await createRedisRefreshTokenFamilyStore({
			client: refreshTokenFamilyClient,
			keyPrefix: "rtfam:",
		}),
	};
};

const commitRotation = () =>
	({ action: "commit", family: { ...FAMILY, activeJti: "jti-new" } }) as const;

describe("updateFamily must not report a rotation Redis refused", () => {
	it("does NOT return committed when the queued SET failed inside MULTI/EXEC", async () => {
		// The exact ioredis shape: EXEC succeeded, the SET inside it did not.
		const { store } = await makeStore([
			[[new Error("OOM command not allowed when used memory > 'maxmemory'"), null]],
		]);

		const result = await store.updateFamily("fam-1", commitRotation).catch((err: unknown) => err);

		expect(result).toBeInstanceOf(Error);
		expect((result as Error).cause).toMatchObject({ message: expect.stringMatching(/^OOM /) });
	});

	it("keeps the driver's own error as the cause, so the operator can tell why", async () => {
		// On `cause`, not in the message: the reply is Redis's text about the
		// command it refused. `loggableError` projects the cause for the log.
		const readonly = new Error("READONLY You can't write against a read only replica.");
		const { store } = await makeStore([[[readonly, null]]]);
		await expect(store.updateFamily("fam-1", commitRotation)).rejects.toMatchObject({
			message: "refreshTokenFamilyClient.exec: a queued command failed inside MULTI/EXEC",
			cause: readonly,
		});
	});

	it("still treats a null EXEC as a CAS conflict and retries (WATCH abort is not an error)", async () => {
		// Load-bearing: turning null into a throw would break refresh-token
		// rotation under contention, which is exactly when it must work.
		const { store, queued } = await makeStore([null, [[null, "OK"]]]);

		const result = await store.updateFamily("fam-1", commitRotation);

		expect(result.outcome).toBe("committed");
		// Two attempts: the aborted one and the one that landed.
		expect(queued).toHaveLength(2);
	});

	it("returns committed when every queued command succeeded", async () => {
		const { store } = await makeStore([[[null, "OK"]]]);
		const result = await store.updateFamily("fam-1", commitRotation);
		expect(result.outcome).toBe("committed");
		if (result.outcome === "committed") {
			expect(result.family.activeJti).toBe("jti-new");
		}
	});
});
