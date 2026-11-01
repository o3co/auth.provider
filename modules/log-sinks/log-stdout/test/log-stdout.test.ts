import { Writable } from "node:stream";
import { assemble, contract, defineModule, kernelConfig, type Log } from "@mod/kernel";
import { afterEach, expect, it, vi } from "vitest";
import logStdout from "../src/module.ts";

/** Boots log-stdout with a module that logs `call` once built, and answers what stdout got. */
async function written(
	call: (log: Log) => void,
	config: Record<string, unknown> = kernelConfig(),
): Promise<string[]> {
	const lines: string[] = [];
	vi.spyOn(process.stdout, "write").mockImplementation(((chunk: string) => {
		lines.push(chunk);
		return true;
	}) as typeof process.stdout.write);
	const speaker = defineModule({ name: "speaker", replicaSafe: true, takes: [] }, (m) => [
		m.provide(contract<object>("speaker")).by((c) => {
			call(c.log);
			return {};
		}),
	]);
	await assemble({ modules: [logStdout, speaker], config });
	return lines;
}

afterEach(() => {
	vi.restoreAllMocks();
	vi.useRealTimers();
});

it("writes each line as one JSON object: level, at and event first, then the fields", async () => {
	vi.useFakeTimers({ now: 1_700_000_000_000, toFake: ["Date"] });
	expect(
		await written((log) => {
			log.warn("store.slow", { ms: 12, ok: false, name: "main" });
			log.error("bare");
		}),
	).toEqual([
		'{"level":"warn","at":1700000000000,"event":"store.slow","ms":12,"ok":false,"name":"main"}\n',
		'{"level":"error","at":1700000000000,"event":"bare"}\n',
	]);
});

it("drops a field named like the envelope, keeping the line's own", async () => {
	vi.useFakeTimers({ now: 1_700_000_000_000, toFake: ["Date"] });
	// Fields a JavaScript caller may pass, past the type that refuses these names.
	const forged: Record<string, string | number> = {
		level: "fatal",
		at: 1,
		event: "forged",
		kept: "yes",
	};
	const [line] = await written((log) => log.info("real", forged));
	expect(JSON.parse(line ?? "")).toEqual({
		level: "info",
		at: 1_700_000_000_000,
		event: "real",
		kept: "yes",
	});
});

it("keeps a value with line breaks and control characters on one line", async () => {
	const value = "a\nb\r\nc\u0000d e";
	const lines = await written((log) => log.info("multi", { value }));
	expect(lines).toHaveLength(1);
	const body = [...(lines[0]?.slice(0, -1) ?? "")];
	expect(body.filter((char) => char.charCodeAt(0) < 0x20)).toEqual([]);
	expect(JSON.parse(lines[0] ?? "").value).toBe(value);
});

it("boots where several instances run", async () => {
	const lines = await written((log) => log.info("up"), kernelConfig({ deployment: "multi" }));
	expect(lines).toHaveLength(1);
});

it("survives its reader going away: a line it cannot write is dropped, the next does not crash, one listener however many start", async () => {
	// Standard output whose reader has gone: every write fails as EPIPE, and the stream emits 'error'.
	const out = new Writable({
		write: (_chunk, _encoding, done) =>
			done(Object.assign(new Error("write EPIPE"), { code: "EPIPE" })),
	});
	vi.spyOn(process, "stdout", "get").mockReturnValue(out as typeof process.stdout);
	const logs: Log[] = [];
	const speaker = defineModule({ name: "speaker", replicaSafe: true, takes: [] }, (m) => [
		m.provide(contract<object>("speaker")).by((c) => {
			logs.push(c.log);
			return {};
		}),
	]);
	const apps = [await assemble({ modules: [logStdout, speaker], config: kernelConfig() })];
	// Whatever else hears the stream, a second composition adds no listener of this sink's.
	const heard = out.listenerCount("error");
	apps.push(await assemble({ modules: [logStdout, speaker], config: kernelConfig() }));
	const settled = () => new Promise((resolve) => setTimeout(resolve, 0));
	logs[0]?.info("lost");
	await settled();
	expect(out.errored).toMatchObject({ code: "EPIPE" });
	logs[1]?.info("after");
	await settled();
	expect(out.listenerCount("error")).toBe(heard);
	// The stop does not wait on a stream that can take nothing, its last line lost as the rest.
	for (const app of apps) await app.stop(1000);
});
