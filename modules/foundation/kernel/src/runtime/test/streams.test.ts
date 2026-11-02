import { Writable } from "node:stream";
import { afterEach, expect, it, vi } from "vitest";
import { assemble, kernelConfig } from "../../contract.ts";

/** A stream whose reader has gone, standing in for one of the process's own. */
const gone = () =>
	new Writable({
		write: (_chunk, _encoding, done) =>
			done(Object.assign(new Error("write EPIPE"), { code: "EPIPE" })),
	});

afterEach(() => {
	vi.restoreAllMocks();
});

it("hears the process's standard output and error once, however many compositions start, so a gone reader ends no process", async () => {
	const out = gone();
	const err = gone();
	vi.spyOn(process, "stdout", "get").mockReturnValue(out as unknown as typeof process.stdout);
	vi.spyOn(process, "stderr", "get").mockReturnValue(err as unknown as typeof process.stderr);
	await assemble({ modules: [], config: kernelConfig() });
	await assemble({ modules: [], config: kernelConfig() });
	for (const stream of [out, err]) {
		const epipe = Object.assign(new Error("write EPIPE"), { code: "EPIPE" });
		expect(() => stream.emit("error", epipe)).not.toThrow();
		expect(stream.listenerCount("error")).toBe(1);
	}
});
