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
 * The session lifecycle's readers and input checks: each reader answers a
 * fresh frozen copy of a well-formed answer and refuses anything else with a
 * TypeError, never a value; each check refuses a caller's input outside the
 * port's rules with a RangeError.
 */

import { describe, expect, it } from "vitest";
import { MAX_DURATION_MS } from "#/config/durations.mjs";
import {
	checkSessionCloseRequest,
	checkSessionParticipant,
	readSessionCloseAnswer,
	readSessionJoinAnswer,
	readSessionLifecycleListing,
	readSessionOpenAnswer,
	readVersionedSessionLifecycle,
	SESSION_CLOSE_CAUSES,
	SESSION_LIFECYCLE_MAX_KEY_LENGTH,
	SESSION_LIFECYCLE_MAX_LISTING,
	SESSION_LIFECYCLE_STATES,
	SESSION_PARTICIPANT_KINDS,
	SESSION_PARTICIPANT_MAX_DATA_LENGTH,
	type SessionClose,
	type SessionCloseRequest,
	type SessionLifecycleRecord,
	type SessionParticipant,
	type StoreGeneration,
	sessionCloseItemOf,
} from "#/index.mjs";

const G = "7b0c3a52-1d0e-4f43-9a51-2f6a1c9e8d10" as StoreGeneration;

const rp: SessionParticipant = { kind: "rp", id: "client-1", data: '{"uri":"https://rp"}' };
const family: SessionParticipant = { kind: "family", id: "fam-1", data: "" };

const active = (): SessionLifecycleRecord => ({
	sub: "user-1",
	state: "active",
	expiresAt: new Date("2026-10-05T01:00:00.000Z"),
	participants: [rp, family],
	close: undefined,
});

const closing = (): SessionLifecycleRecord => ({
	sub: "user-1",
	state: "closing",
	expiresAt: new Date("2026-10-05T01:00:00.000Z"),
	participants: [rp, family],
	close: {
		cause: "rp_logout",
		closingAt: new Date("2026-10-05T00:30:00.000Z"),
		pending: ["user_session", "family:fam-1"],
	},
});

const closed = (): SessionLifecycleRecord => {
	const record = closing();
	return { ...record, state: "closed", close: { ...(record.close as SessionClose), pending: [] } };
};

/** An object whose `key` throws when read. */
const throwing = (base: object, key: string): object =>
	Object.defineProperty({ ...base }, key, {
		get() {
			throw new Error("boom");
		},
		enumerable: true,
	});

describe("the vocabulary", () => {
	it("names three states, three participant kinds and five close causes", () => {
		expect(SESSION_LIFECYCLE_STATES).toEqual(["active", "closing", "closed"]);
		expect(SESSION_PARTICIPANT_KINDS).toEqual(["rp", "family", "federation"]);
		expect(SESSION_CLOSE_CAUSES).toEqual([
			"rp_logout",
			"session_logout",
			"subject_revocation",
			"operator_reset",
			"expiry",
		]);
		expect(Object.isFrozen(SESSION_LIFECYCLE_STATES)).toBe(true);
		expect(Object.isFrozen(SESSION_PARTICIPANT_KINDS)).toBe(true);
		expect(Object.isFrozen(SESSION_CLOSE_CAUSES)).toBe(true);
	});

	it("names a participant's work item by its kind and id", () => {
		expect(sessionCloseItemOf(rp)).toBe("rp:client-1");
		expect(sessionCloseItemOf({ kind: "federation", id: "a:b" })).toBe("federation:a:b");
	});
});

describe("readSessionOpenAnswer and readSessionJoinAnswer", () => {
	it("answer a fresh frozen copy of each outcome", () => {
		for (const outcome of ["opened", "refused"] as const) {
			const answer = { outcome };
			const read = readSessionOpenAnswer(answer);
			expect(read).toEqual({ outcome });
			expect(read).not.toBe(answer);
			expect(Object.isFrozen(read)).toBe(true);
		}
		for (const outcome of ["joined", "closed", "missing"] as const) {
			const read = readSessionJoinAnswer({ outcome });
			expect(read).toEqual({ outcome });
			expect(Object.isFrozen(read)).toBe(true);
		}
	});

	it("refuse another outcome, a non-object and a throwing read with a TypeError", () => {
		for (const bad of [null, undefined, "opened", { outcome: "joined" }, throwing({}, "outcome")]) {
			expect(() => readSessionOpenAnswer(bad as never)).toThrow(TypeError);
		}
		for (const bad of [
			null,
			{ outcome: "opened" },
			{ outcome: "updated" },
			throwing({}, "outcome"),
		]) {
			expect(() => readSessionJoinAnswer(bad as never)).toThrow(TypeError);
		}
	});
});

describe("readVersionedSessionLifecycle", () => {
	it("answers null for null, and a frozen copy of a well-formed record at its generation", () => {
		expect(readVersionedSessionLifecycle(null)).toBeNull();
		for (const record of [active(), closing(), closed()]) {
			const answer = { value: record, generation: G };
			const read = readVersionedSessionLifecycle(answer);
			expect(read).toStrictEqual({ value: record, generation: G });
			expect(Object.isFrozen(read)).toBe(true);
			expect(Object.isFrozen(read?.value)).toBe(true);
			expect(Object.isFrozen(read?.value.participants)).toBe(true);
			// The copy shares no Date with the answer.
			expect(read?.value.expiresAt).not.toBe(record.expiresAt);
			if (record.close !== undefined) {
				expect(read?.value.close?.closingAt).not.toBe(record.close.closingAt);
				expect(Object.isFrozen(read?.value.close?.pending)).toBe(true);
			}
		}
	});

	it("reads an active record whose close is left out as one whose close is undefined, named", () => {
		const { close: _left, ...rest } = active();
		const read = readVersionedSessionLifecycle({
			value: rest as SessionLifecycleRecord,
			generation: G,
		});
		expect(read?.value).toStrictEqual(active());
		expect(Object.hasOwn(read?.value ?? {}, "close")).toBe(true);
	});

	const malformed: ReadonlyArray<readonly [string, unknown]> = [
		["a malformed generation", { value: active(), generation: "" }],
		["no value", { generation: G }],
		["a value that is no object", { value: "record", generation: G }],
		["an empty sub", { value: { ...active(), sub: "" }, generation: G }],
		["a sub that is no string", { value: { ...active(), sub: 7 }, generation: G }],
		["another state", { value: { ...active(), state: "open" }, generation: G }],
		[
			"an invalid expiresAt",
			{ value: { ...active(), expiresAt: new Date(Number.NaN) }, generation: G },
		],
		[
			"an expiresAt that is no Date",
			{ value: { ...active(), expiresAt: "2026-10-05" }, generation: G },
		],
		["participants that are no array", { value: { ...active(), participants: {} }, generation: G }],
		[
			"a participant of another kind",
			{
				value: { ...active(), participants: [{ kind: "client", id: "a", data: "" }] },
				generation: G,
			},
		],
		[
			"a participant with an empty id",
			{ value: { ...active(), participants: [{ kind: "rp", id: "", data: "" }] }, generation: G },
		],
		[
			"a participant whose data is no string",
			{
				value: { ...active(), participants: [{ kind: "rp", id: "a", data: undefined }] },
				generation: G,
			},
		],
		[
			"a participant held twice",
			{ value: { ...active(), participants: [rp, { ...rp, data: "x" }] }, generation: G },
		],
		[
			"an active record with a close",
			{ value: { ...active(), close: closing().close }, generation: G },
		],
		[
			"a closing record with no close",
			{ value: { ...closing(), close: undefined }, generation: G },
		],
		[
			"a closing record with nothing pending",
			{ value: { ...closing(), close: { ...closing().close, pending: [] } }, generation: G },
		],
		[
			"a closed record with work pending",
			{ value: { ...closed(), close: closing().close }, generation: G },
		],
		[
			"a close of another cause",
			{ value: { ...closing(), close: { ...closing().close, cause: "logout" } }, generation: G },
		],
		[
			"an invalid closingAt",
			{
				value: { ...closing(), close: { ...closing().close, closingAt: new Date(Number.NaN) } },
				generation: G,
			},
		],
		[
			"a pending item that is no string",
			{ value: { ...closing(), close: { ...closing().close, pending: [7] } }, generation: G },
		],
		[
			"a pending item held twice",
			{
				value: { ...closing(), close: { ...closing().close, pending: ["a", "a"] } },
				generation: G,
			},
		],
		["a value whose read throws", throwing({ generation: G }, "value")],
		["a field whose read throws", { value: throwing(active(), "participants"), generation: G }],
	];

	for (const [what, answer] of malformed) {
		it(`refuses ${what} with a TypeError`, () => {
			expect(() => readVersionedSessionLifecycle(answer as never)).toThrow(TypeError);
		});
	}
});

describe("readSessionCloseAnswer", () => {
	it("answers missing, and closing or closed with the record and its generation", () => {
		expect(readSessionCloseAnswer({ outcome: "missing" })).toEqual({ outcome: "missing" });
		const read = readSessionCloseAnswer({ outcome: "closing", generation: G, record: closing() });
		expect(read).toStrictEqual({ outcome: "closing", generation: G, record: closing() });
		expect(Object.isFrozen(read)).toBe(true);
		expect(
			readSessionCloseAnswer({ outcome: "closed", generation: G, record: closed() }),
		).toStrictEqual({
			outcome: "closed",
			generation: G,
			record: closed(),
		});
	});

	it("refuses an outcome its record's state does not match, an active record and anything malformed", () => {
		for (const bad of [
			{ outcome: "closing", generation: G, record: closed() },
			{ outcome: "closed", generation: G, record: closing() },
			{ outcome: "closing", generation: G, record: active() },
			{ outcome: "active", generation: G, record: active() },
			{ outcome: "closing", generation: "", record: closing() },
			{ outcome: "closing", generation: G },
			{ outcome: "closing", generation: G, record: { ...closing(), sub: "" } },
			{ outcome: "updated", generation: G },
			null,
		]) {
			expect(() => readSessionCloseAnswer(bad as never)).toThrow(TypeError);
		}
	});
});

describe("readSessionLifecycleListing", () => {
	it("answers a frozen copy of the sids, at most the limit", () => {
		const answer = ["a", "b"];
		const read = readSessionLifecycleListing(answer, 2);
		expect(read).toEqual(["a", "b"]);
		expect(read).not.toBe(answer);
		expect(Object.isFrozen(read)).toBe(true);
	});

	it("refuses more than the limit, a sid named twice, a sid that is no key, and no array", () => {
		expect(() => readSessionLifecycleListing(["a", "b"], 1)).toThrow(TypeError);
		for (const bad of [["a", "a"], [""], [7], "a", null, undefined, { length: 1, 0: "a" }]) {
			expect(() => readSessionLifecycleListing(bad as never, 5)).toThrow(TypeError);
		}
	});
});

describe("checkSessionParticipant", () => {
	it("answers a frozen copy of a participant the port admits", () => {
		const read = checkSessionParticipant(rp);
		expect(read).toStrictEqual(rp);
		expect(read).not.toBe(rp);
		expect(Object.isFrozen(read)).toBe(true);
		expect(
			checkSessionParticipant({
				kind: "federation",
				id: "x".repeat(SESSION_LIFECYCLE_MAX_KEY_LENGTH),
				data: "d".repeat(SESSION_PARTICIPANT_MAX_DATA_LENGTH),
			}),
		).toBeDefined();
	});

	it("refuses anything else with a RangeError", () => {
		for (const bad of [
			null,
			{ kind: "client", id: "a", data: "" },
			{ kind: "rp", id: "", data: "" },
			{ kind: "rp", id: "x".repeat(SESSION_LIFECYCLE_MAX_KEY_LENGTH + 1), data: "" },
			{ kind: "rp", id: 7, data: "" },
			{ kind: "rp", id: "a" },
			{ kind: "rp", id: "a", data: "d".repeat(SESSION_PARTICIPANT_MAX_DATA_LENGTH + 1) },
			throwing({ kind: "rp", data: "" }, "id"),
		]) {
			expect(() => checkSessionParticipant(bad as never)).toThrow(RangeError);
		}
	});
});

describe("checkSessionCloseRequest", () => {
	const request: SessionCloseRequest = {
		cause: "session_logout",
		steps: ["user_session", "subject_index"],
		perParticipant: ["family", "rp"],
		retainMs: 60_000,
	};

	it("answers a frozen copy of a request the port admits", () => {
		const read = checkSessionCloseRequest(request);
		expect(read).toStrictEqual(request);
		expect(Object.isFrozen(read)).toBe(true);
		expect(Object.isFrozen(read.steps)).toBe(true);
		expect(
			checkSessionCloseRequest({ ...request, steps: [], perParticipant: [], retainMs: 0 }),
		).toBeDefined();
		expect(checkSessionCloseRequest({ ...request, retainMs: MAX_DURATION_MS })).toBeDefined();
	});

	it("refuses anything else with a RangeError", () => {
		for (const bad of [
			null,
			{ ...request, cause: "logout" },
			{ ...request, steps: "user_session" },
			{ ...request, steps: ["User"] },
			{ ...request, steps: ["has:colon"] },
			{ ...request, steps: ["a".repeat(65)] },
			{ ...request, steps: ["same", "same"] },
			{ ...request, perParticipant: ["client"] },
			{ ...request, perParticipant: ["rp", "rp"] },
			{ ...request, retainMs: -1 },
			{ ...request, retainMs: 1.5 },
			{ ...request, retainMs: MAX_DURATION_MS + 1 },
			{ ...request, retainMs: Number.NaN },
			throwing(request, "cause"),
		]) {
			expect(() => checkSessionCloseRequest(bad as never)).toThrow(RangeError);
		}
	});

	it("bounds a listing at a thousand", () => {
		expect(SESSION_LIFECYCLE_MAX_LISTING).toBe(1000);
	});
});
