import { defineModule } from "@mod/kernel";
import { spaces, store } from "./contract.ts";
import { memoryStore } from "./memory.ts";
import { section } from "./section.ts";

export default defineModule(
	{ name: "store", section, replicaSafe: false, takes: [spaces] },
	(m) => [
		m.provide(store).by(async (c) => {
			const declared = await c.collect(spaces);
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
			return memoryStore(c.clock, declared);
		}),
	],
);
