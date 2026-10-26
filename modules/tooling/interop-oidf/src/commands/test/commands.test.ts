import { describe, expect, it } from "vitest";
import { systemCommand } from "../commands.ts";

describe("a command a plan runs", () => {
	it("answers what the command wrote to each stream, apart", async () => {
		const said = await systemCommand("sh", ["-c", "echo out; echo err >&2"], { timeoutMs: 10_000 });
		expect(said.stdout).toBe("out\n");
		expect(said.stderr).toBe("err\n");
	});
});
