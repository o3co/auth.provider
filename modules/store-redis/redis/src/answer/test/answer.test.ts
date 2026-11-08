import { Unavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import { answerOf, list } from "../answer.ts";

const reply = (answer: unknown) => `run1\n${JSON.stringify(answer)}`;

it("reads the server and a script's numbers, written as strings or as numbers, and leaves an absent or null one so", () => {
	expect(answerOf(reply({ kind: "counted", count: 2, resetAt: "1700000000000" }))).toEqual({
		server: "run1",
		answer: { kind: "counted", count: 2, resetAt: 1700000000000 },
	});
	expect(answerOf(reply({ kind: "exists", remainingMs: null })).answer).toEqual({
		kind: "exists",
		remainingMs: null,
	});
});

it("answers unavailable where a number is no whole number, never reading it as one", () => {
	for (const resetAt of ["nan", "1.5", "", "1e3", 1.5, "99999999999999999999", true]) {
		expect(() => answerOf(reply({ kind: "limited", resetAt })), String(resetAt)).toThrow(
			Unavailable,
		);
	}
});

it("answers unavailable for a reply holding no run id and JSON object", () => {
	for (const text of [
		"",
		"{}",
		"\n{}",
		"run1\n",
		"run1\nnot json",
		"run1\nnull",
		"run1\n[]",
		"run1\n7",
	]) {
		expect(() => answerOf(text), JSON.stringify(text)).toThrow(Unavailable);
	}
});

it("rebuilds a list cjson wrote as an object, by its count", () => {
	expect(list<string>({ 0: "a", 2: "c" }, 3)).toEqual(["a", undefined, "c"]);
});
