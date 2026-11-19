import type { ErasureJournal } from "@mod/erasure-journal";
import { assemble, BootRefused, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import type { Alone, ErasureMaintenance } from "../../maintenance/maintenance.ts";
import accountErasure from "../../module.ts";
import { enterCommand } from "../commands.ts";

const clock = { now: () => 1_000 };

/**
 * The parts `erasure-enter` runs with: a journal that holds or answers `busy`, and a store answering
 * `alone()` in turn, recording every call either receives; the release fails with `failed` where given.
 */
function parts(seen: (Alone | Error)[], holder?: string, failed?: Error) {
	const calls: string[] = [];
	const journal = {
		hold: async () => {
			calls.push("hold");
			return holder === undefined
				? {
						kind: "held",
						release: async () => {
							calls.push("release");
							if (failed !== undefined) throw failed;
						},
					}
				: { kind: "busy", holder };
		},
	} as unknown as ErasureJournal;
	const maintenance = {
		record: async () => {
			calls.push("record");
			throw new Error("erasure-enter reads no record");
		},
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
	return { parts: { journal, maintenance, clock }, calls };
}

const alone: Alone = { kind: "alone" };

it("enters under the key, shown alone, writing the entry time: code 0", async () => {
	const { parts: p, calls } = parts([alone, alone]);
	expect(await enterCommand(p)([])).toEqual({
		lines: ["entered maintenance under epoch e2; this process was shown alone"],
		code: 0,
	});
	expect(calls).toEqual(["hold", "alone", "enter", "alone", "mark", "release"]);
});

it("refuses any argument with a usage line, calling nothing: code 64", async () => {
	const { parts: p, calls } = parts([alone, alone]);
	expect(await enterCommand(p)(["--force"])).toEqual({
		lines: ["usage: erasure-enter (it takes no arguments)"],
		code: 64,
	});
	expect(calls).toEqual([]);
});

it("does not enter where other processes are attached or not every one can be seen: codes 2 and 3", async () => {
	const cases = [
		[
			{ kind: "accompanied", count: 2 },
			{
				lines: ["not entered: 2 other processes attached; stop them, then run erasure-enter again"],
				code: 2,
			},
		],
		[
			{ kind: "accompanied", count: 1 },
			{
				lines: ["not entered: 1 other process attached; stop them, then run erasure-enter again"],
				code: 2,
			},
		],
		[
			{ kind: "unchecked", reasons: ["replica-unreached", "no-look-offered"] },
			{
				lines: [
					"not entered: not every process could be seen (replica-unreached, no-look-offered); run erasure-enter again once every server answers",
				],
				code: 3,
			},
		],
	] as const;
	for (const [seen, expected] of cases) {
		const { parts: p, calls } = parts([seen]);
		expect(await enterCommand(p)([])).toEqual(expected);
		expect(calls).toEqual(["hold", "alone", "release"]);
	}
});

it("tells an entry not shown alone, the key set, with what was found and the way on: code 4", async () => {
	const cases = [
		[
			{ kind: "accompanied", count: 3 },
			"entered maintenance under epoch e2, but this process was not shown alone (3 other processes attached); the key stays set; stop that process and run erasure-enter again",
		],
		[
			{ kind: "unchecked", reasons: ["replica-unreached"] },
			"entered maintenance under epoch e2, but this process was not shown alone (not every process could be seen: replica-unreached); the key stays set; run erasure-enter again once every server answers",
		],
		[
			new Unavailable("store"),
			"entered maintenance under epoch e2, but this process was not shown alone (the store gave no answer); the key stays set; run erasure-enter again once every server answers",
		],
	] as const;
	for (const [found, line] of cases) {
		const { parts: p, calls } = parts([alone, found]);
		expect(await enterCommand(p)([])).toEqual({ lines: [line], code: 4 });
		expect(calls).toEqual(["hold", "alone", "enter", "alone", "release"]);
	}
});

it("does not run while another command holds the journal, naming the holder where it reads as one printable line: code 5", async () => {
	const named = (holder: string) =>
		`not run: the journal is held (${holder}); run erasure-enter again once its holder ends, or release the hold once its process is gone`;
	const busy = parts([], "pid 41 on node-a since 12:00");
	expect(await enterCommand(busy.parts)([])).toEqual({
		lines: [
			"not run: the journal is held (holder: pid 41 on node-a since 12:00); run erasure-enter again once its holder ends, or release the hold once its process is gone",
		],
		code: 5,
	});
	expect(busy.calls).toEqual(["hold"]);
	const unreadable = [
		"pid 41\nforged line",
		"pid \u001b[31m41",
		"pid 41\u007f",
		"pid 41\u0085forged line",
		"pid 41 ‮apon-edon",
		"pid 41 ⁦node-a⁩",
		"pid​41",
		"﻿pid 41",
		"pid 41 forged line",
		"pid 41 forged paragraph",
		"",
		"x".repeat(201),
	];
	for (const holder of unreadable) {
		expect(await enterCommand(parts([], holder).parts)([]), JSON.stringify(holder)).toEqual({
			lines: [named("unreadable holder")],
			code: 5,
		});
	}
	expect(await enterCommand(parts([], "y".repeat(200)).parts)([])).toEqual({
		lines: [named(`holder: ${"y".repeat(200)}`)],
		code: 5,
	});
});

it("tells an answer whose release failed, its own line first, then the hold left: code 7", async () => {
	const cases = [
		[
			[alone, alone],
			["hold", "alone", "enter", "alone", "mark", "release"],
			"entered maintenance under epoch e2; this process was shown alone",
		],
		[
			[alone, { kind: "accompanied", count: 3 }],
			["hold", "alone", "enter", "alone", "release"],
			"entered maintenance under epoch e2, but this process was not shown alone (3 other processes attached); the key stays set; stop that process and run erasure-enter again",
		],
		[
			[{ kind: "accompanied", count: 2 }],
			["hold", "alone", "release"],
			"not entered: 2 other processes attached; stop them, then run erasure-enter again",
		],
	] as const;
	for (const [seen, expected, line] of cases) {
		const { parts: p, calls } = parts([...seen], undefined, new Unavailable("journal"));
		expect(await enterCommand(p)([])).toEqual({
			lines: [
				line,
				"the journal's hold may be left, as its release failed; release it once this process is gone, before the next erasure command",
			],
			code: 7,
		});
		expect(calls).toEqual(expected);
	}
});

it("lets an outage reach its entry as thrown, the hold released", async () => {
	const outage = new Unavailable("store");
	const { parts: p, calls } = parts([outage]);
	await expect(enterCommand(p)([])).rejects.toBe(outage);
	expect(calls).toEqual(["hold", "alone", "release"]);
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
