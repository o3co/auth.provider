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
 * The Redis `SubjectRevocation` adapter around its client, with a recording
 * client: what it hands the server's clamp, how it says a clamp, and that it
 * refuses a client that cannot clamp. The clamp itself runs against a real
 * Redis in `redis.subjectRevocation.test.mts`.
 */

import {
	consoleLogger,
	DEFAULT_CLOCK_SKEW_MS,
	SUBJECT_REVOCATION_MIN_RETENTION_MS,
} from "@o3co/auth-provider-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SubjectRevocationClient } from "#/clients.mjs";
import { redisSessionStoresModule } from "#/modules/redisSessionStores.mjs";
import {
	createRedisSubjectRevocation,
	redisSubjectRevocationBuilder,
} from "#/subjectRevocation.mjs";

/** The server's clock, as the recording client's script answers it. */
const NOW = Date.UTC(2026, 9, 1);
const UNTIL = new Date(NOW + 600_000);
const AHEAD = new Date(NOW + DEFAULT_CLOCK_SKEW_MS + 60_000);

type Event = { readonly kind: string; readonly args: readonly unknown[] };

/** A client that records each call in `events`, and answers the clamp on `NOW`. */
function recordingClient(events: Event[]): SubjectRevocationClient {
	return {
		get: async () => null,
		advanceRevocationBoundaries: async (...args) => {
			events.push({ kind: "advanceRevocationBoundaries", args });
			return { value: "stored", serverNowMs: NOW };
		},
	};
}

/** A logger that records each warn in `events`, beside the client's calls. */
const recordingLogger = (events: Event[]) => ({
	warn: (obj: Record<string, unknown>, msg: string) => {
		events.push({ kind: "warn", args: [obj, msg] });
	},
});

describe("createRedisSubjectRevocation — the clamp on the server's clock", () => {
	it("hands the server the boundary, the expiry, the grant retention and the skew to clamp by", async () => {
		const events: Event[] = [];
		const store = createRedisSubjectRevocation({
			client: recordingClient(events),
			keyPrefix: "p:",
			logger: recordingLogger(events),
		});
		await store.revokeBefore("u", new Date(NOW), UNTIL);
		await store.revokeSessionsBefore("u", new Date(NOW - 1), UNTIL);
		const wire = {
			expiresAtMs: UNTIL.getTime(),
			grantRetentionMs: SUBJECT_REVOCATION_MIN_RETENTION_MS,
			skewMs: DEFAULT_CLOCK_SKEW_MS,
		};
		expect(events).toEqual([
			{ kind: "advanceRevocationBoundaries", args: ["p:u", "all", { beforeMs: NOW, ...wire }] },
			{
				kind: "advanceRevocationBoundaries",
				args: ["p:u", "sessions", { beforeMs: NOW - 1, ...wire }],
			},
		]);
	});

	it("says at warn, after the write, that the server clamped, and nothing when it did not", async () => {
		const events: Event[] = [];
		const store = createRedisSubjectRevocation({
			client: recordingClient(events),
			keyPrefix: "p:",
			logger: recordingLogger(events),
		});
		await store.revokeBefore("u", new Date(NOW + DEFAULT_CLOCK_SKEW_MS), UNTIL);
		expect(events.map((e) => e.kind)).toEqual(["advanceRevocationBoundaries"]);
		events.length = 0;
		await store.revokeSessionsBefore("u", AHEAD, UNTIL);
		expect(events).toEqual([
			expect.objectContaining({ kind: "advanceRevocationBoundaries" }),
			{
				kind: "warn",
				args: [
					{
						store: "redis",
						subject: "u",
						requestedBefore: AHEAD.toISOString(),
						recordedBefore: new Date(NOW + DEFAULT_CLOCK_SKEW_MS).toISOString(),
					},
					"subject_revocation_boundary_clamped",
				],
			},
		]);
	});

	it("resolves once the boundary is written, when the logger throws or the clock answered is no instant", async () => {
		// The boundary is what ends tokens already issued: losing its signal
		// must not fail the revocation.
		const events: Event[] = [];
		const throwing = createRedisSubjectRevocation({
			client: recordingClient(events),
			keyPrefix: "p:",
			logger: {
				warn: () => {
					throw new Error("log sink down");
				},
			},
		});
		await expect(throwing.revokeBefore("u", AHEAD, UNTIL)).resolves.toBeUndefined();
		const noClock = createRedisSubjectRevocation({
			client: {
				...recordingClient(events),
				advanceRevocationBoundaries: async () => ({ value: "stored", serverNowMs: Number.NaN }),
			},
			keyPrefix: "p:",
			logger: recordingLogger(events),
		});
		await expect(noClock.revokeBefore("u", AHEAD, UNTIL)).resolves.toBeUndefined();
	});

	it("fails the revocation when the write fails", async () => {
		const store = createRedisSubjectRevocation({
			client: {
				...recordingClient([]),
				advanceRevocationBoundaries: async () => {
					throw new Error("ECONNRESET");
				},
			},
			keyPrefix: "p:",
		});
		await expect(store.revokeBefore("u", new Date(NOW), UNTIL)).rejects.toThrow(/ECONNRESET/);
	});

	it.each([
		["an Invalid Date", new Date(Number.NaN)],
		["an object that only answers getTime", { getTime: () => Number.NEGATIVE_INFINITY }],
		["a Date past the representable range", new Date(-1e20)],
	])("refuses %s as before or expiresAt with a RangeError, sending nothing", async (_l, bad) => {
		const events: Event[] = [];
		const store = createRedisSubjectRevocation({
			client: recordingClient(events),
			keyPrefix: "p:",
		});
		const notADate = bad as unknown as Date;
		await expect(store.revokeBefore("u", notADate, UNTIL)).rejects.toThrow(RangeError);
		await expect(store.revokeBefore("u", new Date(NOW), notADate)).rejects.toThrow(RangeError);
		await expect(store.revokeSessionsBefore("u", notADate, UNTIL)).rejects.toThrow(RangeError);
		await expect(store.revokeSessionsBefore("u", new Date(NOW), notADate)).rejects.toThrow(
			RangeError,
		);
		expect(events).toEqual([]);
	});
});

describe("createRedisSubjectRevocation — a client that cannot clamp", () => {
	it("is refused at construction, naming the method it lacks, with nothing said or sent", () => {
		const events: Event[] = [];
		const { advanceRevocationBoundaries: _absent, ...unclamping } = recordingClient(events);
		const construct = () =>
			createRedisSubjectRevocation({
				client: unclamping as never,
				keyPrefix: "p:",
				logger: recordingLogger(events),
			});
		expect(construct).toThrow(/advanceRevocationBoundaries/);
		expect(events).toEqual([]);
	});
});

describe("the clamp's logger, as the module and the builder hand it", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("is core's consoleLogger when none is given", async () => {
		const warn = vi.spyOn(consoleLogger, "warn").mockImplementation(() => undefined);
		const store = createRedisSubjectRevocation({ client: recordingClient([]), keyPrefix: "p:" });
		await store.revokeBefore("u", AHEAD, UNTIL);
		expect(warn.mock.calls.map((call) => call[1])).toEqual(["subject_revocation_boundary_clamped"]);
	});

	it("is the composition's logger in redisSessionStoresModule", async () => {
		const events: Event[] = [];
		const provide = redisSessionStoresModule.provides?.subjectRevocation as unknown as (
			deps: unknown,
		) => ReturnType<typeof createRedisSubjectRevocation>;
		const store = provide({
			subjectRevocationClient: recordingClient(events),
			logger: recordingLogger(events),
			section: { keyPrefix: "ss:" },
		});
		await store.revokeBefore("u", AHEAD, UNTIL);
		expect(events.map((e) => e.kind)).toEqual(["advanceRevocationBoundaries", "warn"]);
	});

	it("is the builder's `logger` option, else the factory context's", async () => {
		const events: Event[] = [];
		const fromOption = await redisSubjectRevocationBuilder(
			{ client: recordingClient(events), logger: recordingLogger(events) },
			{} as never,
		);
		await fromOption.revokeBefore("u", AHEAD, UNTIL);
		const fromContext = await redisSubjectRevocationBuilder({ client: recordingClient(events) }, {
			logger: recordingLogger(events),
		} as never);
		await fromContext.revokeBefore("u", AHEAD, UNTIL);
		expect(events.map((e) => e.kind)).toEqual([
			"advanceRevocationBoundaries",
			"warn",
			"advanceRevocationBoundaries",
			"warn",
		]);
	});
});
