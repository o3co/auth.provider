import type { ErasureJournal } from "@mod/erasure-journal";
import { Unavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import type { Alone, ErasureMaintenance } from "../../maintenance/maintenance.ts";
import { inFrame } from "../frame.ts";

const clock = { now: () => 1_000 };

/**
 * A journal whose hold answers `busy` with `holder` where given, recording its holds and releases;
 * its release rejects with `refused` where given.
 */
function journalOf(calls: string[], holder?: string, refused?: Error) {
	return {
		hold: async () => {
			calls.push("hold");
			if (holder !== undefined) return { kind: "busy", holder } as const;
			return {
				kind: "held",
				release: async () => {
					calls.push("release");
					if (refused !== undefined) throw refused;
				},
			} as const;
		},
	} as unknown as ErasureJournal;
}

/** A store under the key and alone, or not, recording the step's calls. */
function maintenanceOf(calls: string[], held = true) {
	return {
		record: async () => {
			calls.push("record");
			return { epoch: held ? "e1" : null, maintenance: held, requires: [], marks: {} };
		},
		alone: async () => {
			calls.push("alone");
			return { kind: "alone" };
		},
	} as unknown as ErasureMaintenance;
}

/** A store for the entering step, answering `alone()` in turn, recording the step's calls. */
function enteringOf(calls: string[], seen: (Alone | Error)[]) {
	return {
		alone: async () => {
			calls.push("alone");
			const next = seen.shift();
			if (next === undefined) throw new Error("alone() asked once more than the case says");
			if (next instanceof Error) throw next;
			return next;
		},
		enter: async () => {
			calls.push("enter");
			return { kind: "entered", epoch: "e2" };
		},
		mark: async () => {
			calls.push("mark");
			return { kind: "marked" };
		},
	} as unknown as ErasureMaintenance;
}

it("takes the hold, runs the step, runs the body with the epoch, and releases", async () => {
	const calls: string[] = [];
	const parts = { journal: journalOf(calls), maintenance: maintenanceOf(calls), clock };
	const answer = await inFrame(parts, "passing", async (epoch) => {
		calls.push(`body ${epoch}`);
		return { kind: "done" } as const;
	});
	expect(answer).toEqual({ kind: "done" });
	expect(calls).toEqual(["hold", "record", "alone", "body e1", "release"]);
});

it("answers busy where another holds the journal, calling nothing more", async () => {
	const calls: string[] = [];
	const parts = {
		journal: journalOf(calls, "pid 7 on node-a"),
		maintenance: maintenanceOf(calls),
		clock,
	};
	const answer = await inFrame(parts, "passing", async () => {
		calls.push("body");
	});
	expect(answer).toEqual({ kind: "busy", holder: "pid 7 on node-a" });
	expect(calls).toEqual(["hold"]);
});

it("answers the step's refusal without the body, and releases", async () => {
	const calls: string[] = [];
	const parts = { journal: journalOf(calls), maintenance: maintenanceOf(calls, false), clock };
	const answer = await inFrame(parts, "passing", async () => {
		calls.push("body");
	});
	expect(answer).toEqual({ kind: "not-in-maintenance" });
	expect(calls).toEqual(["hold", "record", "release"]);
});

it("releases the hold where the body throws, unavailable or not, and throws it on", async () => {
	for (const thrown of [new Unavailable("store"), new Error("the body's own")]) {
		const calls: string[] = [];
		const parts = { journal: journalOf(calls), maintenance: maintenanceOf(calls), clock };
		await expect(
			inFrame(parts, "passing", async () => {
				throw thrown;
			}),
		).rejects.toBe(thrown);
		expect(calls).toEqual(["hold", "record", "alone", "release"]);
	}
});

it("releases the hold where the step throws, unavailable or not, and throws it on", async () => {
	for (const thrown of [new Unavailable("store"), new Error("the store's own")]) {
		const calls: string[] = [];
		const maintenance = {
			record: async () => {
				calls.push("record");
				throw thrown;
			},
		} as unknown as ErasureMaintenance;
		const parts = { journal: journalOf(calls), maintenance, clock };
		await expect(
			inFrame(parts, "passing", async () => {
				calls.push("body");
			}),
		).rejects.toBe(thrown);
		expect(calls).toEqual(["hold", "record", "release"]);
	}
});

it("releases the hold only once an asynchronous body has finished", async () => {
	const calls: string[] = [];
	let started!: () => void;
	const running = new Promise<void>((resolve) => {
		started = resolve;
	});
	let open!: () => void;
	const gate = new Promise<void>((resolve) => {
		open = resolve;
	});
	const parts = { journal: journalOf(calls), maintenance: maintenanceOf(calls), clock };
	const answer = inFrame(parts, "passing", async () => {
		calls.push("body starts");
		started();
		await gate;
		calls.push("body ends");
		return { kind: "done" } as const;
	});
	await running;
	expect(calls).toEqual(["hold", "record", "alone", "body starts"]);
	open();
	expect(await answer).toEqual({ kind: "done" });
	expect(calls).toEqual(["hold", "record", "alone", "body starts", "body ends", "release"]);
});

it("throws a release's fault in place of the answer, after one attempt, the body run or refused", async () => {
	for (const [held, expected] of [
		[true, ["hold", "record", "alone", "body", "release"]],
		[false, ["hold", "record", "release"]],
	] as const) {
		const calls: string[] = [];
		const fault = new TypeError("the adapter's own");
		const parts = {
			journal: journalOf(calls, undefined, fault),
			maintenance: maintenanceOf(calls, held),
			clock,
		};
		await expect(
			inFrame(parts, "passing", async () => {
				calls.push("body");
				return { kind: "done" } as const;
			}),
		).rejects.toBe(fault);
		expect(calls).toEqual(expected);
	}
});

it("answers hold-left with the answer where the release is unavailable, after one attempt, the body run or refused", async () => {
	for (const [held, answer, expected] of [
		[true, { kind: "done" }, ["hold", "record", "alone", "body", "release"]],
		[false, { kind: "not-in-maintenance" }, ["hold", "record", "release"]],
	] as const) {
		const calls: string[] = [];
		const parts = {
			journal: journalOf(calls, undefined, new Unavailable("journal")),
			maintenance: maintenanceOf(calls, held),
			clock,
		};
		const given = await inFrame(parts, "passing", async () => {
			calls.push("body");
			return { kind: "done" } as const;
		});
		expect(given).toEqual({ kind: "hold-left", answer });
		expect(calls).toEqual(expected);
	}
});

it("throws the body's or the step's throw as it was, whatever its release then throws", async () => {
	for (const failed of [new Unavailable("journal"), new TypeError("the adapter's own")]) {
		const calls: string[] = [];
		const thrown = new Error("the body's own");
		const parts = {
			journal: journalOf(calls, undefined, failed),
			maintenance: maintenanceOf(calls),
			clock,
		};
		await expect(
			inFrame(parts, "passing", async () => {
				calls.push("body");
				throw thrown;
			}),
		).rejects.toBe(thrown);
		expect(calls).toEqual(["hold", "record", "alone", "body", "release"]);

		const stepCalls: string[] = [];
		const outage = new Unavailable("store");
		const maintenance = {
			record: async () => {
				stepCalls.push("record");
				throw outage;
			},
		} as unknown as ErasureMaintenance;
		const stepParts = { journal: journalOf(stepCalls, undefined, failed), maintenance, clock };
		await expect(inFrame(stepParts, "passing", async () => undefined)).rejects.toBe(outage);
		expect(stepCalls).toEqual(["hold", "record", "release"]);
	}
});

it("never runs the body on any entering refusal, and releases once", async () => {
	const alone: Alone = { kind: "alone" };
	const cases = [
		[[{ kind: "accompanied", count: 2 }], "accompanied", ["hold", "alone", "release"]],
		[
			[{ kind: "unchecked", reasons: ["replica-unreached"] }],
			"unchecked",
			["hold", "alone", "release"],
		],
		[
			[alone, { kind: "accompanied", count: 1 }],
			"entered-not-shown-alone",
			["hold", "alone", "enter", "alone", "release"],
		],
		[
			[alone, { kind: "unchecked", reasons: ["replica-unreached"] }],
			"entered-not-shown-alone",
			["hold", "alone", "enter", "alone", "release"],
		],
		[
			[alone, new Unavailable("store")],
			"entered-not-shown-alone",
			["hold", "alone", "enter", "alone", "release"],
		],
	] as const;
	for (const [seen, kind, expected] of cases) {
		const calls: string[] = [];
		let bodies = 0;
		const parts = { journal: journalOf(calls), maintenance: enteringOf(calls, [...seen]), clock };
		const answer = await inFrame(parts, "entering", async () => {
			bodies += 1;
			return { kind: "done" } as const;
		});
		expect(answer.kind, kind).toBe(kind);
		expect(bodies, kind).toBe(0);
		expect(calls, kind).toEqual(expected);
	}
});
