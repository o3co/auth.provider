import { contract, defineModule } from "@mod/kernel";
import { declaredSpaces } from "./checks/checks.ts";
import { spaces, store, storeControl, storeUpkeep } from "./contract.ts";
import { memoryData, memoryProcess } from "./memory/memory.ts";
import { section } from "./section.ts";

/** The one process over the data, whose epoch the store and its upkeep share. */
const opened = contract<ReturnType<typeof memoryProcess>>("store.opened");

export default defineModule(
	{ name: "store", section, replicaSafe: false, takes: [spaces] },
	(m) => [
		m.provide(opened).by(async (c) => {
			const declared = await c.collect(spaces);
			// A malformed declaration refuses the boot (`BuildRefused`) before anything here reads it.
			declaredSpaces(declared);
			const kept = declared.filter(
				(s) => s.guarantees.includes("durable") || s.guarantees.includes("replicated"),
			);
			if (kept.length > 0) {
				if (!c.section["accept-volatile"]) {
					return c.refuse(
						"store.accept-volatile",
						`spaces need durable or replicated, but the memory implementation loses them on restart: ${kept.map((s) => s.name).join(", ")}`,
					);
				}
				// Accepted, yet said at every start: a restart forgets what these spaces keep.
				c.log.warn("store.volatile_accepted", { spaces: kept.map((s) => s.name).join(", ") });
			}
			// Only `true` is never started: a hand-built context may leave it unset.
			return memoryProcess(memoryData(c.clock), declared, c.neverStarted === true);
		}),
		m.provide(store).by(async (c) => (await c.get(opened)).store),
		m.provide(storeControl).by(async (c) => (await c.get(opened)).control),
		m.provide(storeUpkeep).by(async (c) => (await c.get(opened)).upkeep),
	],
);
