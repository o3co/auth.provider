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

import { describe, expect, it } from "vitest";
import { buildActClaim, matchesMayActClient } from "#/act.mjs";
import type { ValidatedToken } from "#/validator/types.mjs";

const tok = (overrides: Partial<ValidatedToken> = {}): ValidatedToken => ({
	sub: "user-1",
	claims: {},
	...overrides,
});

describe("buildActClaim", () => {
	it("returns undefined when no actor_token is present (impersonation)", () => {
		expect(buildActClaim({ subject: tok({ sub: "alice" }), actor: undefined })).toBeUndefined();
	});

	it("does NOT inherit subject.act when no actor_token is present", () => {
		const result = buildActClaim({
			subject: tok({ sub: "alice", act: { sub: "upstream" } }),
			actor: undefined,
		});
		expect(result).toBeUndefined();
	});

	it("returns { sub: <actor.sub> } for simple delegation", () => {
		const result = buildActClaim({
			subject: tok({ sub: "alice" }),
			actor: tok({ sub: "service-a" }),
		});
		expect(result).toEqual({ sub: "service-a" });
	});

	it("nests subject.act inside new act for multi-step delegation", () => {
		const result = buildActClaim({
			subject: tok({ sub: "alice", act: { sub: "service-a" } }),
			actor: tok({ sub: "service-b" }),
		});
		expect(result).toEqual({ sub: "service-b", act: { sub: "service-a" } });
	});

	it("preserves deep nested act chain from subject", () => {
		const result = buildActClaim({
			subject: tok({
				sub: "alice",
				act: { sub: "service-a", act: { sub: "service-upstream" } },
			}),
			actor: tok({ sub: "service-b" }),
		});
		expect(result).toEqual({
			sub: "service-b",
			act: { sub: "service-a", act: { sub: "service-upstream" } },
		});
	});
});

/**
 * The impersonation-path matcher: no actor token exists, so the acting party
 * is the authenticated client and `may_act` is matched against its id.
 */
describe("matchesMayActClient", () => {
	it("matches a single { sub } entry naming the client", () => {
		expect(matchesMayActClient("client-a", { sub: "client-a" })).toBe(true);
	});

	it("matches an array entry naming the client", () => {
		expect(matchesMayActClient("client-a", [{ sub: "svc-b" }, { sub: "client-a" }])).toBe(true);
	});

	it("rejects an entry naming a different party", () => {
		expect(matchesMayActClient("client-a", [{ sub: "svc-b" }])).toBe(false);
	});

	it("rejects an entry that pins iss — a client presents no token to have one", () => {
		expect(matchesMayActClient("client-a", { sub: "client-a", iss: "https://auth.example" })).toBe(
			false,
		);
	});

	it("rejects an empty may_act array (names nobody)", () => {
		expect(matchesMayActClient("client-a", [])).toBe(false);
	});

	it.each([
		["string", "client-a"],
		["number", 1],
		["null", null],
		["undefined", undefined],
		["entry with non-string sub", [{ sub: 1 }]],
		["entry with no sub", [{ other: "client-a" }]],
	])("fails closed on malformed may_act (%s)", (_label, mayAct) => {
		expect(matchesMayActClient("client-a", mayAct)).toBe(false);
	});
});
