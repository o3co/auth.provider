import { afterEach, describe, expect, it, vi } from "vitest";
import {
	assemble,
	BootRefused,
	type BuildContext,
	contract,
	defineModule,
	type Log,
	type LogLine,
	type LogSink,
	logSinks,
	type Module,
} from "../../contract.ts";
import { quietRuntime, recordingLog } from "../../testing.ts";

type Call = (log: Log) => void;

/** A sink module keeping what it gets under `name`. */
function sink(name: string, got: (string | LogLine)[], write?: LogSink["write"]): Module {
	return defineModule({ name, takes: [] }, (m) => [
		m.contribute(logSinks).by(() => ({
			write:
				write ??
				((line) => {
					got.push(name, line);
				}),
		})),
	]);
}

/** A module whose provision logs `call` once built. */
function speaker(call: Call, name = "speaker"): Module {
	return defineModule({ name, takes: [] }, (m) => [
		m.provide(contract<object>(name)).by((c) => {
			call(c.log);
			return {};
		}),
	]);
}

const config = (logging?: unknown) => ({
	kernel: { deployment: "single", ...(logging === undefined ? {} : { logging }) },
});

async function linesOf(call: Call, logging?: unknown): Promise<LogLine[]> {
	const got: (string | LogLine)[] = [];
	await assemble({ modules: [speaker(call), sink("s", got)], config: config(logging) });
	return got.filter((entry): entry is LogLine => typeof entry !== "string");
}

const every: Call = (log) => {
	log.trace("t");
	log.debug("d");
	log.info("i");
	log.warn("w");
	log.error("e");
	log.fatal("f");
};

afterEach(() => {
	vi.restoreAllMocks();
	vi.useRealTimers();
});

describe("log threshold", () => {
	it.each([
		["trace", ["t", "d", "i", "w", "e", "f"]],
		["debug", ["d", "i", "w", "e", "f"]],
		["info", ["i", "w", "e", "f"]],
		["warn", ["w", "e", "f"]],
		["error", ["e", "f"]],
		["fatal", ["f"]],
		["silent", []],
	])("at %s, hands the sinks only the lines at or above it", async (level, events) => {
		const lines = await linesOf(every, { level });
		expect(lines.map((line) => line.event)).toEqual(events);
	});

	it("lets info and above through when the operator sets no level", async () => {
		const levels = ["info", "warn", "error", "fatal"];
		expect((await linesOf(every)).map((line) => line.level)).toEqual(levels);
		expect((await linesOf(every, {})).map((line) => line.level)).toEqual(levels);
	});

	it("refuses a level it does not know, naming the key and never the value", async () => {
		for (const level of ["verbose", "INFO", 3]) {
			const refused = await assemble({ modules: [], config: config({ level }) }).catch(
				(error: unknown) => error,
			);
			expect(refused).toBeInstanceOf(BootRefused);
			const refusals = (refused as BootRefused).refusals;
			expect(refusals.map((r) => r.where)).toEqual(["kernel.logging.level"]);
			expect(JSON.stringify(refusals)).not.toContain(String(level));
		}
	});

	it("refuses a logging section holding anything but level, and other keys in the kernel section", async () => {
		for (const [logging, where] of [
			[{ level: "info", format: "json" }, "kernel.logging"],
			["info", "kernel.logging"],
		] as const) {
			const refused = (await assemble({ modules: [], config: config(logging) }).catch(
				(error: unknown) => error,
			)) as BootRefused;
			expect(refused.refusals.map((r) => r.where)).toEqual([where]);
		}
		const extra = (await assemble({
			modules: [],
			config: { kernel: { deployment: "single", format: "json" } },
		}).catch((error: unknown) => error)) as BootRefused;
		expect(extra.refusals.map((r) => r.where)).toEqual(["kernel"]);
	});
});

describe("log sinks", () => {
	it("hands each sink the level, event, kernel time and fields, the fields never replacing the others", async () => {
		vi.useFakeTimers({ now: 1_700_000_000_000, toFake: ["Date"] });
		const lines = await linesOf((log) =>
			log.warn("e", { level: "error", event: "x", at: 1, n: 2 }),
		);
		expect(lines).toEqual([
			{
				level: "warn",
				event: "e",
				at: 1_700_000_000_000,
				fields: { level: "error", event: "x", at: 1, n: 2 },
			},
		]);
		expect(Object.isFrozen(lines[0])).toBe(true);
		expect(Object.isFrozen(lines[0]?.fields)).toBe(true);
		expect((await linesOf((log) => log.info("bare")))[0]?.fields).toEqual({});
	});

	it("hands every line to every sink in module order, past a sink that throws, never throwing to the caller", async () => {
		const got: (string | LogLine)[] = [];
		const stdout = vi.spyOn(process.stdout, "write");
		let returned = false;
		await assemble({
			modules: [
				sink("first", got),
				sink("broken", got, () => {
					throw new Error("down");
				}),
				speaker((log) => {
					log.info("a");
					log.error("b");
					returned = true;
				}),
				sink("second", got),
			],
			config: config(),
		});
		expect(returned).toBe(true);
		expect(stdout).not.toHaveBeenCalled();
		expect(got.map((entry) => (typeof entry === "string" ? entry : entry.event))).toEqual([
			"first",
			"a",
			"second",
			"a",
			"first",
			"b",
			"second",
			"b",
		]);
	});

	it("builds the sinks before the other parts and drops the lines logged while they build", async () => {
		const got: (string | LogLine)[] = [];
		const needed = contract<object>("needed");
		const logging = defineModule({ name: "logging", takes: [needed] }, (m) => [
			m.contribute(logSinks).by(async (c) => {
				c.log.error("from the sink");
				await c.get(needed);
				return { write: (line: LogLine) => void got.push(line) };
			}),
		]);
		const before = defineModule({ name: "before", takes: [] }, (m) => [
			m.provide(needed).by((c) => {
				c.log.error("while sinks build");
				return {};
			}),
		]);
		await assemble({
			modules: [before, speaker((log) => log.error("after")), logging],
			config: config(),
		});
		expect(got.map((line) => (line as LogLine).event)).toEqual(["after"]);
	});

	it("hands a failed periodic run's line to the sinks", async () => {
		vi.useFakeTimers();
		const got: (string | LogLine)[] = [];
		const failing = defineModule({ name: "failing", takes: [] }, (m) => [
			m.provide(contract<object>("failing")).by((c: BuildContext<unknown>) => {
				c.every(100, async () => {
					throw new Error("once");
				});
				return {};
			}),
		]);
		const app = await assemble({ modules: [failing, sink("s", got)], config: config() });
		await app.start();
		await vi.advanceTimersByTimeAsync(100);
		await app.stop(1000);
		expect(got).toEqual([
			"s",
			expect.objectContaining({
				level: "warn",
				event: "kernel.every_failed",
				fields: { module: "failing", kind: "Error" },
			}),
		]);
	});

	it("keeps running a failing periodic task when its warn line meets a throwing sink or log", async () => {
		vi.useFakeTimers();
		let runs = 0;
		const failing = defineModule({ name: "failing", takes: [] }, (m) => [
			m.provide(contract<object>("failing")).by((c: BuildContext<unknown>) => {
				c.every(100, async () => {
					runs++;
					throw new Error("again");
				});
				return {};
			}),
		]);
		const throwing = () => {
			throw new Error("log down");
		};
		const got: (string | LogLine)[] = [];
		const sinks = [sink("broken", got, throwing), sink("s", got)];
		const viaSinks = await assemble({ modules: [failing, ...sinks], config: config() });
		const log = {
			trace: throwing,
			debug: throwing,
			info: throwing,
			warn: throwing,
			error: throwing,
			fatal: throwing,
		};
		const passed = await assemble({
			modules: [failing],
			config: config(),
			runtime: quietRuntime({ log }),
		});
		for (const app of [viaSinks, passed]) {
			await app.start();
			await vi.advanceTimersByTimeAsync(200);
			await app.stop(1000);
		}
		expect(runs).toBe(4);
		expect(got.filter((entry) => entry === "s")).toHaveLength(2);
	});

	it("never throws, whatever a passed log or the fields do", async () => {
		const throwing = () => {
			throw new Error("log down");
		};
		const log = {
			trace: throwing,
			debug: throwing,
			info: throwing,
			warn: throwing,
			error: throwing,
			fatal: throwing,
		};
		const fields = {
			get n(): number {
				throw new Error("unreadable");
			},
		};
		let returned = 0;
		const call: Call = (l) => {
			l.error("e");
			l.warn("w", fields);
			returned++;
		};
		await assemble({ modules: [speaker(call)], config: config(), runtime: quietRuntime({ log }) });
		await linesOf(call);
		expect(returned).toBe(2);
	});

	it("leaves a runtime a test passes as it is: no threshold, no sinks", async () => {
		const got: (string | LogLine)[] = [];
		const recorded = recordingLog();
		await assemble({
			modules: [speaker(every), sink("s", got)],
			config: config({ level: "silent" }),
			runtime: quietRuntime({ log: recorded.log }),
		});
		expect(got).toEqual([]);
		expect(recorded.lines().map((line) => line.event)).toEqual(["t", "d", "i", "w", "e", "f"]);
	});

	it("writes nothing while no module contributes a sink", async () => {
		const stdout = vi.spyOn(process.stdout, "write");
		const stderr = vi.spyOn(process.stderr, "write");
		await assemble({ modules: [speaker(every)], config: config() });
		expect([stdout.mock.calls, stderr.mock.calls]).toEqual([[], []]);
	});
});
