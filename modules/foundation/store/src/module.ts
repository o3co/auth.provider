import { defineModule } from "@mod/kernel";
import { spaces, store } from "./contract.ts";
import { memoryStore } from "./memory.ts";
import { section } from "./section.ts";

export default defineModule({ name: "store", section, replicaSafe: false }, (m) => [
	m.provide(store).by(async (c) => {
		const declared = await c.collect(spaces);
		const kept = declared.filter(
			(s) => s.guarantees.includes("durable") || s.guarantees.includes("replicated"),
		);
		if (kept.length > 0 && !c.section["accept-volatile"]) {
			return c.refuse(
				"store.accept-volatile",
				`spaces need durable or replicated, but the memory implementation loses them on restart: ${kept.map((s) => s.name).join(", ")}`,
			);
		}
		return memoryStore(c.clock, declared);
	}),
]);
