import type { ErasureJournal } from "@mod/erasure-journal";
import { Unavailable } from "@mod/kernel";
import { expect, expectTypeOf, it } from "vitest";
import type { Alone, ErasureMaintenance } from "../../maintenance/maintenance.ts";
import { inFrame, type Refused } from "../frame.ts";

const clock = { now: () => 1_000 };

/** How a release fails: it rejects or throws the value, or it returns no promise at all. */
type Failing =
	| { readonly how: "rejects" | "throws"; readonly value: unknown }
	| { readonly how: "returns-nothing" };

/**
 * A journal whose hold answers `busy` with `holder` where given, recording its holds and releases;
 * its release fails as `failing` says where given.
 */
function journalOf(calls: string[], holder?: string, failing?: Failing) {
	return {
		hold: async () => {
			calls.push("hold");
			if (holder !== undefined) return { kind: "busy", holder } as const;
			return {
				kind: "held",
				release: () => {
					calls.push("release");
					if (failing === undefined) return Promise.resolve();
					if (failing.how === "returns-nothing") return undefined;
					if (failing.how === "throws") throw failing.value;
					return Promise.reject(failing.value);
				},
			} as const;
		},
	} as unknown as ErasureJournal;
}

/** An outage as kernel marks it: its own class, or another copy's error carrying the same mark. */
const outages = (): unknown[] => [
	new Unavailable("journal"),
	Object.assign(new Error("journal unavailable"), {
		[Symbol.for("@mod/kernel.unavailable")]: true,
	}),
];

/** What is no outage: a name alone, another error, and values that are no error at all. */
const faults = (): unknown[] => [
	Object.assign(new Error("journal unavailable"), { name: "Unavailable" }),
	new TypeError("the adapter's own"),
	"the adapter's own",
	null,
	undefined,
];

/** Every way a release can fail, each value rejected and thrown. */
const failings = (values: unknown[]): Failing[] =>
	values.flatMap((value): Failing[] => [
		{ how: "rejects", value },
		{ how: "throws", value },
	]);

const named = (failing: Failing | undefined) =>
	failing === undefined
		? "released"
		: failing.how === "returns-nothing"
			? "returns-nothing"
			: `${failing.how} ${String(failing.value)}`;

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

it("answers busy where the journal is held, calling nothing more", async () => {
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

it("throws the step's or the body's throw as it was, whatever its release then does, after one attempt", async () => {
	const releases = [
		undefined,
		...failings([...outages(), ...faults()]),
		{ how: "returns-nothing" } as const,
	];
	for (const thrown of [new Error("the own"), ...outages(), ...faults()]) {
		for (const failing of releases) {
			const seen = `${String(thrown)} / ${named(failing)}`;
			const calls: string[] = [];
			const parts = {
				journal: journalOf(calls, undefined, failing),
				maintenance: maintenanceOf(calls),
				clock,
			};
			await expect(
				inFrame(parts, "passing", async () => {
					calls.push("body");
					throw thrown;
				}),
				seen,
			).rejects.toBe(thrown);
			expect(calls, seen).toEqual(["hold", "record", "alone", "body", "release"]);

			const stepCalls: string[] = [];
			const maintenance = {
				record: async () => {
					stepCalls.push("record");
					throw thrown;
				},
			} as unknown as ErasureMaintenance;
			const stepParts = { journal: journalOf(stepCalls, undefined, failing), maintenance, clock };
			await expect(
				inFrame(stepParts, "passing", async () => undefined),
				seen,
			).rejects.toBe(thrown);
			expect(stepCalls, seen).toEqual(["hold", "record", "release"]);
		}
	}
});

it("answers hold-left with the answer where the release is unavailable, after one attempt, the body run or refused", async () => {
	for (const failing of failings(outages())) {
		for (const [held, answer, expected] of [
			[true, { kind: "done" }, ["hold", "record", "alone", "body", "release"]],
			[false, { kind: "not-in-maintenance" }, ["hold", "record", "release"]],
		] as const) {
			const seen = `${named(failing)} / ${answer.kind}`;
			const calls: string[] = [];
			const parts = {
				journal: journalOf(calls, undefined, failing),
				maintenance: maintenanceOf(calls, held),
				clock,
			};
			const given = await inFrame(parts, "passing", async () => {
				calls.push("body");
				return { kind: "done" } as const;
			});
			expect(given, seen).toEqual({ kind: "hold-left", answer });
			expect(calls, seen).toEqual(expected);
		}
	}
});

it("gives the answer as it was where the release returns no promise, after one attempt, the body run or refused", async () => {
	for (const [held, answer, expected] of [
		[true, { kind: "done" }, ["hold", "record", "alone", "body", "release"]],
		[false, { kind: "not-in-maintenance" }, ["hold", "record", "release"]],
	] as const) {
		const calls: string[] = [];
		const parts = {
			journal: journalOf(calls, undefined, { how: "returns-nothing" }),
			maintenance: maintenanceOf(calls, held),
			clock,
		};
		const given = await inFrame(parts, "passing", async () => {
			calls.push("body");
			return { kind: "done" } as const;
		});
		expect(given, answer.kind).toEqual(answer);
		expect(calls, answer.kind).toEqual(expected);
	}
});

it("throws anything else a release throws, as it was, in place of the answer, after one attempt, the body run or refused", async () => {
	for (const failing of failings(faults())) {
		for (const [held, expected] of [
			[true, ["hold", "record", "alone", "body", "release"]],
			[false, ["hold", "record", "release"]],
		] as const) {
			const seen = `${named(failing)} / ${held ? "answered" : "refused"}`;
			const calls: string[] = [];
			const parts = {
				journal: journalOf(calls, undefined, failing),
				maintenance: maintenanceOf(calls, held),
				clock,
			};
			await expect(
				inFrame(parts, "passing", async () => {
					calls.push("body");
					return { kind: "done" } as const;
				}),
				seen,
			).rejects.toBe("value" in failing ? failing.value : undefined);
			expect(calls, seen).toEqual(expected);
		}
	}
});

it("gives as hold-left only the step's refusal or the body's answer, never busy or under-key", () => {
	type Done = { readonly kind: "done" };
	type Given = Awaited<ReturnType<typeof inFrame<Done>>>;
	expectTypeOf<Extract<Given, { kind: "hold-left" }>["answer"]>().toEqualTypeOf<Refused | Done>();
});
