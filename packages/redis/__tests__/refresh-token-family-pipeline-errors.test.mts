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

// Regression test for the defect found sweeping PR #352: `updateFamily`'s CAS
// inspected its `EXEC` reply for `null` — the WATCH-abort signal — but not for
// per-command errors. ioredis reports a failed queued command *inside* the
// reply and resolves rather than rejecting, because `EXEC` itself succeeded.
// So a `SET` Redis refused (OOM, a replica gone read-only, a `maxmemory-policy`
// eviction refusal) came back as a non-null array, sailed past the `null`
// check, and `updateFamily` returned `{ outcome: "committed" }` for a rotation
// that never landed.
//
// That is the worst shape a refresh-token store can fail in: the caller issues
// the new refresh token believing the family was advanced, while Redis still
// holds the old `activeJti`. The next use of that token is then indistinguishable
// from replay, and replay detection revokes the family — logging the user out
// and, depending on the deployment, raising a security alert for a token theft
// that never happened.
//
// These tests drive the real store through the real ioredis wrapper, with only
// the driver faked, so removing the reply check in `ioredis.mts` fails them.

import type { RefreshTokenFamily } from "@o3co/auth-provider-core";
import type { Redis } from "ioredis";
import { describe, expect, it, vi } from "vitest";
import { makeIoredisClients } from "../src/ioredis.mjs";
import { createRedisRefreshTokenFamilyStore } from "../src/refresh-token-family.mjs";

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
		on: vi.fn(),
		quit: vi.fn(async () => "OK"),
		disconnect: vi.fn(),
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

const makeStore = (execReplies: unknown[]) => {
	const { io, queued } = makeFakeIoredis(execReplies);
	const { refreshTokenFamilyClient } = makeIoredisClients(io);
	return {
		queued,
		store: createRedisRefreshTokenFamilyStore({
			client: refreshTokenFamilyClient,
			keyPrefix: "rtfam:",
		}),
	};
};

const commitRotation = () =>
	({ action: "commit", family: { ...FAMILY, activeJti: "jti-new" } }) as const;

describe("#352 regression — updateFamily must not report a rotation Redis refused", () => {
	it("does NOT return committed when the queued SET failed inside MULTI/EXEC", async () => {
		// The exact ioredis shape: EXEC succeeded, the SET inside it did not.
		const { store } = makeStore([
			[[new Error("OOM command not allowed when used memory > 'maxmemory'"), null]],
		]);

		const result = await store.updateFamily("fam-1", commitRotation).catch((err: unknown) => err);

		// Pre-fix this was `{ outcome: "committed", ... }` — a rotation the
		// store never persisted, reported as durable.
		expect(result).toBeInstanceOf(Error);
		expect((result as Error).message).toMatch(/OOM/);
	});

	it("surfaces the driver's own message so the operator can tell why", async () => {
		const { store } = makeStore([
			[[new Error("READONLY You can't write against a read only replica."), null]],
		]);
		await expect(store.updateFamily("fam-1", commitRotation)).rejects.toThrow(/READONLY/);
	});

	it("still treats a null EXEC as a CAS conflict and retries (WATCH abort is not an error)", async () => {
		// Load-bearing: turning null into a throw would break refresh-token
		// rotation under contention, which is exactly when it must work.
		const { store, queued } = makeStore([null, [[null, "OK"]]]);

		const result = await store.updateFamily("fam-1", commitRotation);

		expect(result.outcome).toBe("committed");
		// Two attempts: the aborted one and the one that landed.
		expect(queued).toHaveLength(2);
	});

	it("returns committed when every queued command succeeded", async () => {
		const { store } = makeStore([[[null, "OK"]]]);
		const result = await store.updateFamily("fam-1", commitRotation);
		expect(result.outcome).toBe("committed");
		if (result.outcome === "committed") {
			expect(result.family.activeJti).toBe("jti-new");
		}
	});
});
