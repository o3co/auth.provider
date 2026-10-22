import { expect, it } from "vitest";
import { refusalsIn } from "../refused.ts";

it("reads every refusal a refused app wrote, past the log lines before them", () => {
	const output = [
		'{"level":"warn","event":"redis.error"}',
		"refused redis: the store cannot be reached",
		'{"level":"warn","event":"redis.error"}',
		"refused rate-limit: needs a store that is reached",
		"",
	].join("\n");
	expect(refusalsIn(output)).toEqual([
		"redis: the store cannot be reached",
		"rate-limit: needs a store that is reached",
	]);
});

it("finds none where the app wrote no refusal, so an exit without one is no refusal", () => {
	expect(refusalsIn('{"level":"warn","event":"redis.error"}\n')).toEqual([]);
	expect(refusalsIn("")).toEqual([]);
});
