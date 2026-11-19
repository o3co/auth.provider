import type { ErasureJournal } from "@mod/erasure-journal";
import { Unavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import type { ErasureMaintenance } from "../../maintenance/maintenance.ts";
import { inFrame } from "../frame.ts";

const clock = { now: () => 1_000 };

/** A journal whose hold answers `busy` with `holder` where given, recording its holds and releases. */
function journalOf(calls: string[], holder?: string) {
	return {
		hold: async () => {
			calls.push("hold");
			if (holder !== undefined) return { kind: "busy", holder } as const;
			return {
				kind: "held",
				release: async () => {
					calls.push("release");
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

it("releases the hold where the step throws unavailable", async () => {
	const calls: string[] = [];
	const outage = new Unavailable("store");
	const maintenance = {
		record: async () => {
			calls.push("record");
			throw outage;
		},
	} as unknown as ErasureMaintenance;
	const parts = { journal: journalOf(calls), maintenance, clock };
	await expect(inFrame(parts, "passing", async () => undefined)).rejects.toBe(outage);
	expect(calls).toEqual(["hold", "record", "release"]);
});
