import { beforeAll, describe, expect, it, TestRunner } from "vitest";
import { leaveOut } from "../src/skip.ts";

type Task = {
	name: string;
	type: string;
	result?: { state: string; note?: string };
	tasks?: Task[];
};
const siblings = () => (TestRunner.getCurrentTest()?.suite?.tasks ?? []) as Task[];
const named = (tasks: Task[], name: string) => tasks.find((t) => t.name === name);

describe("leaving a scene out", () => {
	it("from a test", () => {
		leaveOut("not-in-pattern: lacks @mod/dpop");
		throw new Error("ran after being left out");
	});

	describe("from a suite's beforeAll", () => {
		beforeAll(() => leaveOut("not-in-pattern: pauses the Store"));
		it("first", () => {
			throw new Error("ran after being left out");
		});
		describe("nested", () => {
			it("second", () => {
				throw new Error("ran after being left out");
			});
		});
	});

	it("skips the test with its reason, and each test of the suite with the suite's", () => {
		const tasks = siblings();
		expect(named(tasks, "from a test")?.result).toMatchObject({
			state: "skip",
			note: "not-in-pattern: lacks @mod/dpop",
		});
		const suite = named(tasks, "from a suite's beforeAll");
		expect(suite?.result?.note).toBe("not-in-pattern: pauses the Store");
		const first = named(suite?.tasks ?? [], "first");
		const second = named(named(suite?.tasks ?? [], "nested")?.tasks ?? [], "second");
		expect([first?.result?.state, second?.result?.state]).toEqual(["skip", "skip"]);
	});
});
