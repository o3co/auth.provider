import { expect, it } from "vitest";
import { jsonAnswer, noStore } from "../src/contract.ts";

it("answers JSON kept out of caches, with cookies only when it is given some", () => {
	expect(jsonAnswer(400, { error: "invalid_request" })).toEqual({
		status: 400,
		headers: noStore,
		body: { json: { error: "invalid_request" } },
	});
	expect(jsonAnswer(200, {}, { cookies: [] })).not.toHaveProperty("cookies");
	expect(
		jsonAnswer(200, { ok: true }, { cookies: ["a=1"], headers: { "retry-after": "5" } }),
	).toEqual({
		status: 200,
		headers: { ...noStore, "retry-after": "5" },
		body: { json: { ok: true } },
		cookies: ["a=1"],
	});
});
