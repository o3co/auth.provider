import { assemble, contract, defineModule, kernelConfig } from "@mod/kernel";
import { afterEach, expect, it, vi } from "vitest";
import { drained, type Outgoing } from "../src/drain.ts";
import logStdout from "../src/module.ts";

/** A stand-in for standard output whose writes stay queued until released, in order. */
function queuing() {
	const queued: (() => void)[] = [];
	const out: Outgoing = {
		get writableLength() {
			return queued.length;
		},
		write: (_chunk: string, done?: (error?: Error | null) => void) => {
			queued.push(() => done?.());
			return false;
		},
	};
	const release = () => {
		for (const done of queued.splice(0)) done();
	};
	return { out, queued, release };
}

afterEach(() => {
	vi.restoreAllMocks();
});

it("waits at stop for the lines it queued to be handed on, then lets the stop end", async () => {
	const { out, queued, release } = queuing();
	vi.spyOn(process.stdout, "write").mockImplementation(out.write as typeof process.stdout.write);
	vi.spyOn(process.stdout, "writableLength", "get").mockImplementation(() => out.writableLength);
	const speaker = defineModule({ name: "speaker", replicaSafe: true, takes: [] }, (m) => [
		m.provide(contract<object>("speaker")).by((c) => {
			c.onStop(() => c.log.warn("speaker.stopped"));
			return {};
		}),
	]);
	const app = await assemble({ modules: [logStdout, speaker], config: kernelConfig() });
	let stopped = false;
	const stop = app.stop(5000).then(() => {
		stopped = true;
	});
	await new Promise((resolve) => setTimeout(resolve, 20));
	// The line the speaker logged as it stopped is queued, and the stop waits on it.
	expect(queued.length).toBeGreaterThan(0);
	expect(stopped).toBe(false);
	release();
	await stop;
	expect(stopped).toBe(true);
});

it("answers at once where nothing is queued, or where the stop's signal has aborted", async () => {
	const { out, release } = queuing();
	await drained(out, new AbortController().signal);
	out.write("line\n");
	const aborted = new AbortController();
	aborted.abort();
	await drained(out, aborted.signal);
	// Aborted while waiting, it answers then, the lines left queued.
	const later = new AbortController();
	const waiting = drained(out, later.signal);
	later.abort();
	await waiting;
	release();
});

it("never throws, where the output refuses the write", async () => {
	const broken: Outgoing = {
		writableLength: 1,
		write: () => {
			throw new Error("write after end");
		},
	};
	await expect(drained(broken, new AbortController().signal)).resolves.toBeUndefined();
});
