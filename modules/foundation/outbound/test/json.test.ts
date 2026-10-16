import { expect, it } from "vitest";
import { jsonObjectOf } from "../src/contract.ts";

const answer = (status: number, text: string) => ({
	status,
	headers: new Map<string, string>(),
	body: new TextEncoder().encode(text),
});

it("reads one JSON object from a 200 answer, frozen, and tells any other answer apart by its status", () => {
	const read = jsonObjectOf(answer(200, '{"keys":[{"kid":"a"}]}'));
	expect(read).toEqual({ kind: "object", value: { keys: [{ kid: "a" }] } });
	if (read.kind !== "object") throw new Error(read.kind);
	expect(Object.isFrozen((read.value.keys as object[])[0])).toBe(true);
	expect(jsonObjectOf(answer(404, '{"a":1}'))).toEqual({ kind: "other", status: 404 });
	for (const text of ["{nope", "[1]", "null", '"x"', ""]) {
		expect(jsonObjectOf(answer(200, text)), text).toEqual({ kind: "other", status: 200 });
	}
	// Bytes that are not UTF-8 are not JSON, rather than read with replacement characters.
	const malformed = {
		...answer(200, ""),
		body: Uint8Array.of(0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d),
	};
	expect(jsonObjectOf(malformed)).toEqual({ kind: "other", status: 200 });
});

it("reads an answer of another status only when the caller names that status", () => {
	const refused = answer(400, '{"error":"invalid_grant"}');
	expect(jsonObjectOf(refused)).toEqual({ kind: "other", status: 400 });
	expect(jsonObjectOf(refused, 400)).toEqual({ kind: "object", value: { error: "invalid_grant" } });
	expect(jsonObjectOf(answer(200, '{"a":1}'), 400)).toEqual({ kind: "other", status: 200 });
	expect(jsonObjectOf(answer(400, "[1]"), 400)).toEqual({ kind: "other", status: 400 });
});
