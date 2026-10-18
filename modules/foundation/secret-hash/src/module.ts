import { defineModule } from "@mod/kernel";
import { z } from "zod";
import { checkerWith, defaultMaxConcurrent, placesOf } from "./checker.ts";
import { secretCheckers } from "./contract.ts";
import { matches } from "./hashes.ts";

const section = z.strictObject({
	"max-concurrent": z
		.number()
		.int()
		.min(1)
		.max(1024)
		.prefault(defaultMaxConcurrent)
		.describe(
			"Secret checks under way at once in this assembly, every checker it makes together; one more is unavailable at once, before any hashing.",
		),
});

export default defineModule({ name: "secret-hash", section, replicaSafe: true }, (m) => [
	m.provide(secretCheckers).by((c) => {
		const places = placesOf(c.section["max-concurrent"]);
		return { checkerOf: (inUse) => checkerWith(inUse, c.random.bytes, matches, places) };
	}),
]);
