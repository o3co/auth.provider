import type { ErasureJournal } from "@mod/erasure-journal";
import { assemble, BootRefused, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import type { Alone, ErasureMaintenance } from "../../maintenance/maintenance.ts";
import accountErasure from "../../module.ts";
import { commandCodes, enterCommand } from "../commands.ts";

const clock = { now: () => 1_000 };

/** The parts `erasure-enter` runs with: a journal that holds or answers `busy`, and a store answering `alone()` in turn. */
function parts(seen: (Alone | Error)[], holder?: string) {
	const calls: string[] = [];
	const journal = {
		hold: async () =>
			holder === undefined
				? {
						kind: "held",
						release: async () => {
							calls.push("release");
						},
					}
				: { kind: "busy", holder },
	} as unknown as ErasureJournal;
	const maintenance = {
		alone: async () => {
			const next = seen.shift();
			if (next === undefined) throw new Error("alone() asked once more than the case says");
			if (next instanceof Error) throw next;
			return next;
		},
		enter: async () => ({ kind: "entered", epoch: "e2" }),
		mark: async () => {
			calls.push("mark");
			return { kind: "marked" };
		},
	} as unknown as ErasureMaintenance;
	return { parts: { journal, maintenance, clock }, calls };
}

const alone: Alone = { kind: "alone" };

it("enters under the key, shown alone, writing the entry time: code 0", async () => {
	const { parts: p, calls } = parts([alone, alone]);
	expect(await enterCommand(p)([])).toEqual({
		lines: ["entered maintenance under epoch e2; this process was shown alone"],
		code: 0,
	});
	expect(calls).toEqual(["mark", "release"]);
});

it("refuses any argument with a usage line, taking nothing: code 64", async () => {
	const { parts: p, calls } = parts([]);
	expect(await enterCommand(p)(["--force"])).toEqual({
		lines: ["usage: erasure-enter (it takes no arguments)"],
		code: commandCodes.usage,
	});
	expect(calls).toEqual([]);
});

it("does not enter where other processes are attached or not every one can be seen: codes 2 and 3", async () => {
	const accompanied = await enterCommand(parts([{ kind: "accompanied", count: 2 }]).parts)([]);
	expect(accompanied).toEqual({
		lines: ["not entered: 2 other processes attached; stop them, then run erasure-enter again"],
		code: 2,
	});
	const one = await enterCommand(parts([{ kind: "accompanied", count: 1 }]).parts)([]);
	expect(one.lines[0]).toContain("1 other process attached");
	const unchecked = await enterCommand(
		parts([{ kind: "unchecked", reasons: ["replica-unreached", "no-look-offered"] }]).parts,
	)([]);
	expect(unchecked).toEqual({
		lines: [
			"not entered: not every process could be seen (replica-unreached, no-look-offered); run erasure-enter again once every server answers",
		],
		code: 3,
	});
});

it("tells an entry not shown alone, the key set, with what was found and the way on: code 4", async () => {
	const cases = [
		[{ kind: "accompanied", count: 3 }, "3 other processes attached", "stop that process"],
		[
			{ kind: "unchecked", reasons: ["replica-unreached"] },
			"not every process could be seen: replica-unreached",
			"once every server answers",
		],
		[new Unavailable("store"), "the store gave no answer", "once every server answers"],
	] as const;
	for (const [found, shown, way] of cases) {
		const { parts: p, calls } = parts([alone, found]);
		const run = await enterCommand(p)([]);
		expect(run.code).toBe(commandCodes.enteredNotShownAlone);
		expect(run.lines).toHaveLength(1);
		expect(run.lines[0]).toContain(
			"entered maintenance under epoch e2, but this process was not shown alone",
		);
		expect(run.lines[0]).toContain(shown);
		expect(run.lines[0]).toContain("the key stays set");
		expect(run.lines[0]).toContain(way);
		expect(calls).toEqual(["release"]);
	}
});

it("does not run while another command holds the journal, naming the holder where it reads as one printable line: code 5", async () => {
	const busy = await enterCommand(parts([], "pid 41 on node-a since 12:00").parts)([]);
	expect(busy).toEqual({
		lines: [
			"not run: another erasure command holds the journal (holder: pid 41 on node-a since 12:00); run erasure-enter again once it ends, or release its hold once its process is gone",
		],
		code: 5,
	});
	for (const holder of ["pid 41\nforged line", "pid \u001b[31m41", "", "x".repeat(201)]) {
		const run = await enterCommand(parts([], holder).parts)([]);
		expect(run.code, JSON.stringify(holder)).toBe(5);
		expect(run.lines[0], JSON.stringify(holder)).toContain("(unreadable holder)");
		expect(run.lines[0]).not.toContain("holder: ");
		expect(run.lines[0]).not.toContain("\n");
		expect(run.lines[0]).not.toContain("\u001b");
	}
	const longest = await enterCommand(parts([], "y".repeat(200)).parts)([]);
	expect(longest.lines[0]).toContain("y".repeat(200));
});

it("lets an outage reach its entry as thrown, the hold released", async () => {
	const outage = new Unavailable("store");
	const { parts: p, calls } = parts([outage]);
	await expect(enterCommand(p)([])).rejects.toBe(outage);
	expect(calls).toEqual(["release"]);
});

it("refuses the boot where no wiring provides erasure's maintenance interface, or no journal is composed", async () => {
	const refused = await assemble({
		modules: [accountErasure],
		config: kernelConfig(),
		runtime: quietRuntime(),
	}).catch((error: unknown) => error);
	expect(refused).toBeInstanceOf(BootRefused);
	expect((refused as BootRefused).refusals).toEqual(
		expect.arrayContaining([
			{ where: "account-erasure", reason: "no module provides account-erasure.maintenance" },
			{ where: "account-erasure", reason: "no module provides erasure-journal" },
		]),
	);
});
