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
import { describe, expect, it, vi } from "vitest";
import type { UserSessionStoreClient } from "../src/clients.mjs";
import { createRedisUserSessionStore } from "../src/userSessionStore.mjs";
import {
	PRE_UPGRADE_FEDERATED_ENVELOPE,
	PRE_UPGRADE_FEDERATED_SID,
} from "./support/preUpgradeEnvelopes.mjs";

// Lightweight in-memory mock with a `seed()` helper to inject corrupt
// payloads directly into the Redis store. Matches the exactly-what-we-test
// surface: only `get` is exercised by these tests.
const makeMockClient = (): UserSessionStoreClient & {
	seed: (key: string, raw: string) => void;
	read: (key: string) => string | undefined;
} => {
	const store = new Map<string, string>();
	const set = ((..._args: unknown[]) => Promise.resolve("OK" as const)) as never;
	return {
		set,
		get: async (k: string) => store.get(k) ?? null,
		del: async (k: string) => (store.delete(k) ? 1 : 0),
		replaceIfUnchanged: async (k: string, expected: string, next: string) => {
			if (store.get(k) !== expected) return false;
			store.set(k, next);
			return true;
		},
		seed: (key, raw) => store.set(key, raw),
		read: (key) => store.get(key),
	};
};

const validEnvelope = {
	sid: "sid-1",
	sub: "user-1",
	authTimeMs: Date.now(),
	createdAtMs: Date.now(),
	expiresAtMs: Date.now() + 60_000,
	claims: { iss: "https://auth.example" },
};

describe("RedisUserSessionStore.get — corrupt envelope validation", () => {
	const keyPrefix = "sess:";

	it("returns the session for a valid envelope", async () => {
		const client = makeMockClient();
		const store = createRedisUserSessionStore({ client, keyPrefix });
		client.seed(`${keyPrefix}sid-1`, JSON.stringify(validEnvelope));
		const result = await store.get("sid-1");
		expect(result).not.toBeNull();
		expect(result?.sid).toBe("sid-1");
		expect(result?.sub).toBe("user-1");
	});

	it("returns null and logs json_parse warn on malformed JSON (object-first call shape)", async () => {
		const logger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
		const client = makeMockClient();
		const store = createRedisUserSessionStore({ client, keyPrefix, logger });
		client.seed(`${keyPrefix}sid-bad`, "{not-valid-json}}");

		const result = await store.get("sid-bad");
		expect(result).toBeNull();
		// Object-first per the Logger interface: structured fields are the
		// 1st arg, the human-readable message is the 2nd arg.
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ sid: "sid-bad", reason: "json_parse" }),
			"user_session_corrupt_envelope",
		);
	});

	// Each missing or invalid field on its own makes `get()` return null and
	// emit a `shape_invalid` warn, so an implementation that validated only
	// `expiresAtMs` would still fail these. `expiresAtMs: undefined` must not
	// bypass the expiry filter.
	it.each([
		["sid missing", { ...validEnvelope, sid: undefined as unknown as string }],
		["sub missing", { ...validEnvelope, sub: undefined as unknown as string }],
		["authTimeMs missing", { ...validEnvelope, authTimeMs: undefined as unknown as number }],
		["createdAtMs missing", { ...validEnvelope, createdAtMs: undefined as unknown as number }],
		["expiresAtMs missing", { ...validEnvelope, expiresAtMs: undefined as unknown as number }],
		[
			"expiresAtMs non-numeric",
			{ ...validEnvelope, expiresAtMs: "not-a-number" as unknown as number },
		],
		["expiresAtMs null", { ...validEnvelope, expiresAtMs: null as unknown as number }],
		["claims null", { ...validEnvelope, claims: null as unknown as Record<string, unknown> }],
		[
			"claims is array (not object)",
			{ ...validEnvelope, claims: [] as unknown as Record<string, unknown> },
		],
		// Timestamps must be safe integers in the JS Date valid range. A finite
		// number outside it (`Number.MAX_VALUE`, `2 ** 60`, fractional ms)
		// loses precision through `new Date(ms)` and could either propagate
		// `Invalid Date` or appear effectively-never-expiring against
		// `expiresAtMs <= Date.now()`.
		[
			"expiresAtMs > MAX_DATE_MS (8.64e15)",
			{ ...validEnvelope, expiresAtMs: 8_640_000_000_000_001 as unknown as number },
		],
		[
			"expiresAtMs unsafe-integer above 2^53",
			{ ...validEnvelope, expiresAtMs: Number.MAX_VALUE as unknown as number },
		],
		["expiresAtMs fractional", { ...validEnvelope, expiresAtMs: 1.5 as unknown as number }],
		["expiresAtMs negative", { ...validEnvelope, expiresAtMs: -1 as unknown as number }],
		["authTimeMs unsafe-integer", { ...validEnvelope, authTimeMs: (2 ** 60) as unknown as number }],
		["createdAtMs fractional", { ...validEnvelope, createdAtMs: 1.5 as unknown as number }],
		// The MFA ADR's D9: `authentication` is absent (written before it
		// existed) or well-formed. Anything else is not read as either — a
		// session whose record of a second factor cannot be read is refused,
		// never taken for a pre-upgrade one to be split again.
		["authentication null", { ...validEnvelope, authentication: null }],
		["authentication an array", { ...validEnvelope, authentication: [] }],
		["authentication without primary", { ...validEnvelope, authentication: {} }],
		["authentication.primary a number", { ...validEnvelope, authentication: { primary: 1 } }],
		["authentication.primary empty", { ...validEnvelope, authentication: { primary: "" } }],
		[
			"authentication.federation a number",
			{ ...validEnvelope, authentication: { primary: "fed", federation: 1 } },
		],
		[
			"authentication.federation null",
			{ ...validEnvelope, authentication: { primary: "fed", federation: null } },
		],
		[
			"authentication.upstreamAmr not an array",
			{ ...validEnvelope, authentication: { primary: "fed", upstreamAmr: "hwk" } },
		],
		[
			"authentication.upstreamAmr holding a number",
			{ ...validEnvelope, authentication: { primary: "fed", upstreamAmr: ["hwk", 1] } },
		],
		[
			"authentication.mfaAtMs negative",
			{ ...validEnvelope, authentication: { primary: "pwd", mfaAtMs: -1 } },
		],
		[
			"authentication.mfaAtMs fractional",
			{ ...validEnvelope, authentication: { primary: "pwd", mfaAtMs: 1.5 } },
		],
		[
			"authentication.mfaAtMs a string",
			{ ...validEnvelope, authentication: { primary: "pwd", mfaAtMs: "1" } },
		],
		// `enrollmentFacts` is absent (none recorded, or written before the
		// key) or what the type admits. Anything else is not read as absent:
		// a session whose facts cannot be read is refused, never taken for one
		// that recorded none.
		["enrollmentFacts null", { ...validEnvelope, enrollmentFacts: null }],
		["enrollmentFacts a string", { ...validEnvelope, enrollmentFacts: "enrolled" }],
		["enrollmentFacts an array", { ...validEnvelope, enrollmentFacts: [] }],
		[
			"enrollmentFacts.witness unknown",
			{ ...validEnvelope, enrollmentFacts: { witness: "yes", mailAddress: "address" } },
		],
		[
			"enrollmentFacts without witness",
			{ ...validEnvelope, enrollmentFacts: { mailAddress: "address" } },
		],
		[
			"enrollmentFacts without mailAddress",
			{ ...validEnvelope, enrollmentFacts: { witness: "enrolled" } },
		],
		[
			"enrollmentFacts.mailAddress an address",
			{ ...validEnvelope, enrollmentFacts: { witness: "enrolled", mailAddress: "a@b.example" } },
		],
		[
			"enrollmentFacts.mailAddress a boolean",
			{ ...validEnvelope, enrollmentFacts: { witness: "enrolled", mailAddress: true } },
		],
	])("returns null and logs shape_invalid warn for %s", async (_label, corrupt) => {
		const logger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
		const client = makeMockClient();
		const store = createRedisUserSessionStore({ client, keyPrefix, logger });
		client.seed(`${keyPrefix}sid-corrupt`, JSON.stringify(corrupt));

		const result = await store.get("sid-corrupt");
		expect(result).toBeNull();
		// Object-first per the Logger interface: structured fields are the
		// 1st arg, the human-readable message is the 2nd arg.
		expect(logger.warn).toHaveBeenCalledWith(
			expect.objectContaining({ sid: "sid-corrupt", reason: "shape_invalid" }),
			"user_session_corrupt_envelope",
		);
	});

	it("reads an envelope written before authentication existed as a session with authentication undefined", async () => {
		// The bytes a release before the key wrote, captured from its writer:
		// nothing to split here — `sessionAuthentication` / `vouchedAmr` split
		// it as it is read.
		const client = makeMockClient();
		const store = createRedisUserSessionStore({ client, keyPrefix });
		client.seed(`${keyPrefix}${PRE_UPGRADE_FEDERATED_SID}`, PRE_UPGRADE_FEDERATED_ENVELOPE);
		const result = await store.get(PRE_UPGRADE_FEDERATED_SID);
		expect(result).toHaveProperty("authentication", undefined);
		expect(result?.amr).toEqual(["hwk", "fed"]);
		expect(result?.claims).toEqual({ email: "alice@example.com", name: "Alice" });
	});

	it("reads authentication from the envelope, every field named", async () => {
		const client = makeMockClient();
		const store = createRedisUserSessionStore({ client, keyPrefix });
		const mfaAtMs = Date.now() - 1_000;
		client.seed(
			`${keyPrefix}sid-1`,
			JSON.stringify({
				...validEnvelope,
				amr: ["pwd", "otp", "mfa"],
				authentication: { primary: "pwd", mfaAtMs },
			}),
		);
		expect((await store.get("sid-1"))?.authentication).toStrictEqual({
			primary: "pwd",
			federation: undefined,
			upstreamAmr: undefined,
			mfaAt: new Date(mfaAtMs),
		});
	});

	it("reads enrollmentFacts from the envelope, and an envelope without them as a session that has none", async () => {
		const client = makeMockClient();
		const store = createRedisUserSessionStore({ client, keyPrefix });
		client.seed(
			`${keyPrefix}sid-1`,
			JSON.stringify({
				...validEnvelope,
				enrollmentFacts: { witness: "malformed", mailAddress: "unreadable" },
			}),
		);
		expect((await store.get("sid-1"))?.enrollmentFacts).toStrictEqual({
			witness: "malformed",
			mailAddress: "unreadable",
		});
		client.seed(`${keyPrefix}sid-2`, JSON.stringify({ ...validEnvelope, sid: "sid-2" }));
		expect(await store.get("sid-2")).not.toHaveProperty("enrollmentFacts");
		client.seed(`${keyPrefix}${PRE_UPGRADE_FEDERATED_SID}`, PRE_UPGRADE_FEDERATED_ENVELOPE);
		expect(await store.get(PRE_UPGRADE_FEDERATED_SID)).not.toHaveProperty("enrollmentFacts");
	});

	it("returns null and writes through consoleLogger when no logger is injected", async () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		try {
			const client = makeMockClient();
			const store = createRedisUserSessionStore({ client, keyPrefix });
			client.seed(`${keyPrefix}sid-corrupt`, "{not-valid-json}");
			const result = await store.get("sid-corrupt");
			expect(result).toBeNull();
			expect(warn).toHaveBeenCalledWith(
				expect.objectContaining({ sid: "sid-corrupt", reason: "json_parse" }),
				"user_session_corrupt_envelope",
			);
		} finally {
			warn.mockRestore();
		}
	});
});

describe("RedisUserSessionStore.recordSecondFactor — what it reads and how often it tries", () => {
	const keyPrefix = "sess:";
	const passwordEnvelope = {
		...validEnvelope,
		amr: ["pwd"],
		authentication: { primary: "pwd" },
	};

	it("reads a corrupt envelope as gone, as get does: null, one warn, nothing written", async () => {
		const logger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
		const client = makeMockClient();
		const store = createRedisUserSessionStore({ client, keyPrefix, logger });
		client.seed(`${keyPrefix}sid-1`, JSON.stringify({ ...validEnvelope, authentication: null }));
		expect(
			await store.recordSecondFactor("sid-1", { amr: ["otp", "mfa"], at: new Date() }),
		).toBeNull();
		expect(logger.warn).toHaveBeenCalledTimes(1);
		expect(logger.warn).toHaveBeenCalledWith(
			{ sid: "sid-1", reason: "shape_invalid" },
			"user_session_corrupt_envelope",
		);
		expect(client.read(`${keyPrefix}sid-1`)).toBe(
			JSON.stringify({ ...validEnvelope, authentication: null }),
		);
	});

	it("re-reads and retries when another write moved the session, and lands on what that write left", async () => {
		const client = makeMockClient();
		const store = createRedisUserSessionStore({ client, keyPrefix });
		client.seed(`${keyPrefix}sid-1`, JSON.stringify(passwordEnvelope));
		const replace = client.replaceIfUnchanged;
		let interfered = false;
		client.replaceIfUnchanged = async (k, expected, next) => {
			if (!interfered) {
				// Another step-up lands between this one's read and its write.
				interfered = true;
				client.seed(k, JSON.stringify({ ...passwordEnvelope, amr: ["pwd", "hwk", "mfa"] }));
			}
			return replace(k, expected, next);
		};
		const recorded = await store.recordSecondFactor("sid-1", {
			amr: ["otp", "mfa"],
			at: new Date(),
		});
		expect(recorded?.amr).toEqual(["pwd", "hwk", "mfa", "otp"]);
		expect(JSON.parse(client.read(`${keyPrefix}sid-1`) as string).amr).toEqual([
			"pwd",
			"hwk",
			"mfa",
			"otp",
		]);
	});

	it("gives up after a bounded number of lost compare-and-sets, with an error and nothing written", async () => {
		const client = makeMockClient();
		const store = createRedisUserSessionStore({ client, keyPrefix });
		client.seed(`${keyPrefix}sid-1`, JSON.stringify(passwordEnvelope));
		const lost = vi.fn(async () => false);
		client.replaceIfUnchanged = lost;
		await expect(
			store.recordSecondFactor("sid-1", { amr: ["otp", "mfa"], at: new Date() }),
		).rejects.toThrow(/recordSecondFactor/);
		// Five tries: the first and four re-reads.
		expect(lost).toHaveBeenCalledTimes(5);
		expect(client.read(`${keyPrefix}sid-1`)).toBe(JSON.stringify(passwordEnvelope));
	});
});

describe("RedisUserSessionStore — what the store needs from its client, and what it keeps of a newer release's envelope", () => {
	const keyPrefix = "sess:";

	it("refuses at construction a client without replaceIfUnchanged, naming it, rather than failing the first step-up", () => {
		const { replaceIfUnchanged: _omitted, ...withoutIt } = makeMockClient();
		expect(() =>
			createRedisUserSessionStore({
				client: withoutIt as unknown as UserSessionStoreClient,
				keyPrefix,
			}),
		).toThrow(/replaceIfUnchanged/);
	});

	it("keeps what a newer release added to the envelope — beside the session and inside authentication — when it records a second factor", async () => {
		// A rolling upgrade, then a step-up on a replica still on this release:
		// what the newer release wrote beside the fields this one knows must
		// survive the write.
		const client = makeMockClient();
		const store = createRedisUserSessionStore({ client, keyPrefix });
		client.seed(
			`${keyPrefix}sid-1`,
			JSON.stringify({
				...validEnvelope,
				amr: ["pwd"],
				addedLater: { kept: true },
				authentication: { primary: "pwd", addedLater: { kept: true } },
			}),
		);
		const verifiedAt = new Date();
		const recorded = await store.recordSecondFactor("sid-1", {
			amr: ["otp", "mfa"],
			at: verifiedAt,
		});
		expect(recorded?.amr).toEqual(["pwd", "otp", "mfa"]);
		const written = JSON.parse(client.read(`${keyPrefix}sid-1`) as string);
		expect(written.addedLater).toEqual({ kept: true });
		expect(written.authentication).toEqual({
			primary: "pwd",
			addedLater: { kept: true },
			mfaAtMs: verifiedAt.getTime(),
		});
	});
});
