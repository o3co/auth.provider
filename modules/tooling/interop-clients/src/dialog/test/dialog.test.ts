import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { type AdapterCommand, type Ask, converse } from "../dialog.ts";

const fake: AdapterCommand = {
	command: process.execPath,
	args: [join(import.meta.dirname, "fixtures", "adapter.ts")],
	cwd: import.meta.dirname,
	env: { PATH: process.env.PATH ?? "" },
};

const callback = async (_: Ask): Promise<Record<string, unknown>> => ({
	location: "https://rp.example/cb?code=c",
});
const run = (script: unknown[], answer = callback) =>
	converse(fake, { flow: "login", script }, answer, 5_000);

describe("a flow's dialog with an adapter", () => {
	it("answers each ask and ends with the adapter's result, keeping the lines both ways", async () => {
		const asked: unknown[] = [];
		const dialog = await run(
			[{ ask: "browse", url: "https://op.example/authorize" }, { result: { sub: "alice" } }],
			async (ask: Ask) => {
				asked.push(ask);
				return { location: "https://rp.example/cb?code=c" };
			},
		);
		expect(asked).toEqual([{ ask: "browse", url: "https://op.example/authorize" }]);
		expect(dialog.outcome).toEqual({ kind: "result", result: { sub: "alice" } });
		expect(dialog.transcript.map((l) => l.to)).toEqual(["in", "out", "in", "out"]);
		expect(dialog.stderr).toContain("the library speaks here");
	});

	it("ends with the adapter's error, its type and message", async () => {
		const dialog = await run([{ error: { type: "OPError", message: "invalid_grant" } }]);
		expect(dialog.outcome).toEqual({ kind: "error", type: "OPError", message: "invalid_grant" });
	});

	it("ends as a protocol error on a line that is no JSON, an exit before a result, or no result in time", async () => {
		expect((await run(["not json"])).outcome).toMatchObject({
			kind: "error",
			type: "protocol",
			message: "not a JSON line: not json",
		});
		expect((await run([{ hello: 1 }])).outcome).toMatchObject({ type: "protocol" });
		expect((await run(["exit"])).outcome).toMatchObject({
			type: "protocol",
			message: expect.stringContaining("exited (4) before a result"),
		});
		const slow = await converse(fake, { flow: "login", script: ["hang"] }, async () => ({}), 300);
		expect(slow.outcome).toEqual({
			kind: "error",
			type: "protocol",
			message: "no result in 300ms",
		});
	});

	it("ends as a protocol error where answering an ask fails", async () => {
		const dialog = await run([{ ask: "browse", url: "x" }], async () => {
			throw new Error("the login was refused");
		});
		expect(dialog.outcome).toMatchObject({
			type: "protocol",
			message: expect.stringContaining("the login was refused"),
		});
	});
});
