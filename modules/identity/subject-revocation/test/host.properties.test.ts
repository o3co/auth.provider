/**
 * The boot gate across compositions: for any guards, erasers (erasable or not), store (fencing or
 * not, telling whether erasure is enabled or not) and mark (on or off, readable at boot or not),
 * and then any run of the store going down and coming back and the mark turning readable or not,
 * the boot and every readiness answer are as the cards state, and no composition that is not
 * covered is ever ready where erasure is enabled.
 *
 * The model below is the cards', line by line (subject-revocation/README.md, Invariants and
 * Vocabulary; src/erasure/README.md, Invariants): where it and the code disagree, one of them is
 * wrong. The examples in erasure.test.ts pin one composition per rule; this runs them all.
 *
 * Per-PR runs are fixed: FC_SEED (default 20261111) and FC_RUNS (default 300).
 */
import { type Eraser, erasers } from "@mod/erasure-extensions";
import {
	assemble,
	BootRefused,
	type BuildContext,
	contract,
	defineModule,
	kernelConfig,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import fc from "fast-check";
import { expect, it } from "vitest";
import { erasureGuards } from "../src/contract.ts";
import revocationModule from "../src/module.ts";
import { boundaryStore } from "../src/store.ts";
import { memoryBoundaries } from "./stores.ts";

const seed = Number(process.env.FC_SEED ?? 20261111);
const numRuns = Number(process.env.FC_RUNS ?? 300);
const rule = "this node must never serve a deployment where erasure is enabled";

interface Composition {
	readonly guards: number;
	readonly erasers: readonly { readonly name: string; readonly erasable: boolean }[];
	readonly fences: boolean;
	readonly tells: boolean;
	/** Whether erasure is enabled, as the store's mark holds it. */
	readonly enabled: boolean;
	/** Whether the mark can be read at boot; the rest of the store answers as `down` says. */
	readonly readableAtBoot: boolean;
	readonly downAtBoot: boolean;
}
/** After boot: readiness asked, the mark turning readable or not, the store going down or coming back. */
type After =
	| { readonly kind: "ready?" }
	| { readonly kind: "mark"; readonly readable: boolean }
	| { readonly kind: "store"; readonly down: boolean };

const composition: fc.Arbitrary<Composition> = fc.record({
	guards: fc.nat({ max: 2 }),
	erasers: fc
		.array(fc.boolean(), { maxLength: 3 })
		.map((erasable) => erasable.map((e, i) => ({ name: `owner${i}`, erasable: e }))),
	fences: fc.boolean(),
	tells: fc.boolean(),
	enabled: fc.boolean(),
	readableAtBoot: fc.boolean(),
	downAtBoot: fc.boolean(),
});
const after: fc.Arbitrary<After> = fc.oneof(
	{ arbitrary: fc.constant({ kind: "ready?" as const }), weight: 3 },
	{
		arbitrary: fc.record({ kind: fc.constant("mark" as const), readable: fc.boolean() }),
		weight: 2,
	},
	{ arbitrary: fc.record({ kind: fc.constant("store" as const), down: fc.boolean() }), weight: 1 },
);

/** What the cards state a composition does: its boot, its warnings, and then its readiness. */
function stated(c: Composition) {
	const unerasable = c.erasers.filter((e) => !e.erasable).map((e) => e.name);
	// Vocabulary: covered is "the store fences, a module guards erasure, and every composed eraser is erasable".
	const covered = c.fences && c.guards > 0 && unerasable.length === 0;
	const cannotTell = !c.tells;
	// "Covered … is known without the store": the gate reads the mark at start only where not covered.
	// "One not covered reads the mark at start: enabled refuses the boot"; "an unread mark never refuses the boot".
	const readAtBoot = !covered && !cannotTell && c.readableAtBoot;
	const refused = readAtBoot && c.enabled;
	/** The mark as the process holds it: read once, held for the process; unread is read again. */
	let held: "on" | "off" | undefined = readAtBoot ? (c.enabled ? "on" : "off") : undefined;
	return {
		covered,
		refused,
		unerasable,
		// "Where the store cannot tell …, with a warning at every start (`erasure_unknown`)".
		unknownWarned: cannotTell,
		// "Each owner that cannot erase is warned at every start (`erasure_unerasable`, with `owners`)",
		// the exclusion's rule named "in its warning" where the store cannot tell.
		unerasableWarned: unerasable.length > 0,
		ruleInUnerasable: cannotTell,
		/** Readiness now, the mark readable or not: the probe reads it where not covered. */
		ready: (readable: boolean): "ready" | "unready" => {
			// "a covered composition starts and is ready whatever the store answers".
			if (covered) return "ready";
			// "Where the store cannot tell …, start and readiness read it as off".
			if (cannotTell) return "ready";
			if (held === undefined && readable) held = c.enabled ? "on" : "off";
			// "unread starts it unready … until the mark reads off"; enabled and not covered is never ready.
			return held === "off" ? "ready" : "unready";
		},
	};
}

const eraserOf = (name: string, erasable: boolean): Eraser => ({
	name,
	erasable,
	online: async () => ({ reports: [], logoutGaps: 0 }),
	window: async () => ({ reports: [], logoutGaps: 0 }),
	migrate: async () => [],
});

/** The real module over the stand-in boundary store, with the guards and erasers given. */
async function composed(c: Composition) {
	const stores = memoryBoundaries(() => 0, { fence: c.fences, erasureEnabled: c.tells });
	stores.erasure.on = c.enabled;
	stores.erasure.unreadable = !c.readableAtBoot;
	if (c.downAtBoot) stores.down.unavailable("read", "save", "update");
	const recorded = recordingLog();
	let context: BuildContext<unknown> | undefined;
	const booted = await assemble({
		modules: [
			revocationModule,
			defineModule({ name: "boundaries", replicaSafe: false, takes: [] }, (m) => [
				m.provide(boundaryStore).by(() => stores.boundaries),
			]),
			defineModule({ name: "guards", replicaSafe: false, takes: [] }, (m) =>
				Array.from({ length: c.guards }, (_, i) =>
					m.contribute(erasureGuards).by(() => ({ name: `guard${i}` })),
				),
			),
			defineModule({ name: "owners", replicaSafe: false, takes: [] }, (m) =>
				c.erasers.map((e) => m.contribute(erasers).by(() => eraserOf(e.name, e.erasable))),
			),
			defineModule({ name: "asker", replicaSafe: false, takes: [] }, (m) => [
				m.provide(contract<object>("host-asker")).by((built) => {
					context = built;
					return {};
				}),
			]),
		],
		config: kernelConfig(),
		runtime: quietRuntime({ clock: { now: () => 0 }, log: recorded.log }),
	}).catch((error: unknown) => {
		if (error instanceof BootRefused) return error;
		throw error;
	});
	const lines = (event: string) => recorded.lines().filter((l) => l.event === event);
	return {
		stores,
		refused: booted instanceof BootRefused ? JSON.stringify(booted.refusals) : undefined,
		ready: async () => (await context?.readinessReport(1000))?.answer,
		unknown: () => lines("subject-revocation.erasure_unknown"),
		unerasable: () => lines("subject-revocation.erasure_unerasable"),
	};
}

it("boots and answers readiness across every composition as the cards state, and never ready where erasure is enabled and the composition does not cover it", async () => {
	await fc.assert(
		fc.asyncProperty(composition, fc.array(after, { maxLength: 8 }), async (c, steps) => {
			const model = stated(c);
			const app = await composed(c);

			// The boot: refused only where not covered, the mark read and enabled, naming the owners.
			if (model.refused) {
				expect(app.refused, "a boot the cards refuse").toMatch(/subject-revocation/);
				for (const owner of model.unerasable) expect(app.refused).toContain(owner);
				return;
			}
			expect(app.refused, "a boot the cards start").toBeUndefined();

			// The warnings at start.
			expect(app.unknown().length, "erasure_unknown").toBe(model.unknownWarned ? 1 : 0);
			for (const line of app.unknown()) expect(String(line.fields.reason)).toContain(rule);
			const unerasable = app.unerasable();
			expect(unerasable.length, "erasure_unerasable").toBe(model.unerasableWarned ? 1 : 0);
			for (const line of unerasable) {
				expect(String(line.fields.owners).split(" ").sort()).toEqual([...model.unerasable].sort());
				expect(String(line.fields.reason).includes(rule), "the rule in erasure_unerasable").toBe(
					model.ruleInUnerasable,
				);
			}

			// Readiness, at start and after each change.
			let readable = c.readableAtBoot;
			const answers: { readonly ready: string | undefined; readonly readable: boolean }[] = [];
			const ask = async () => {
				const ready = await app.ready();
				expect(ready, `readiness, the mark ${readable ? "readable" : "unread"}`).toBe(
					model.ready(readable),
				);
				answers.push({ ready, readable });
			};
			await ask();
			for (const st of steps) {
				if (st.kind === "mark") {
					readable = st.readable;
					app.stores.erasure.unreadable = !readable;
				} else if (st.kind === "store") {
					if (st.down) app.stores.down.unavailable("read", "save", "update");
					else app.stores.down.restore();
				} else {
					await ask();
				}
			}
			// Never ready where erasure is enabled and the composition does not cover it, cannot-tell
			// being the stated exclusion.
			if (c.enabled && !model.covered && c.tells) {
				expect(answers.map((a) => a.ready)).not.toContain("ready");
			}
		}),
		{ seed, numRuns },
	);
}, 120_000);
