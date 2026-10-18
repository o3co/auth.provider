import { contract, defineModule } from "@mod/kernel";
import { z } from "zod";
import { defaultMaxConcurrent, limitChecks } from "./checker.ts";

const section = z.strictObject({
	"max-concurrent": z
		.number()
		.int()
		.min(1)
		.max(1024)
		.prefault(defaultMaxConcurrent)
		.describe(
			"Secret checks under way at once in this process, every caller's together; one more is unavailable at once, before any hashing.",
		),
});

/** The process's limit on checks under way, set as the module is built. */
const maxConcurrent = contract<number>("secret-hash.max-concurrent");

export default defineModule({ name: "secret-hash", section, replicaSafe: true }, (m) => [
	m.provide(maxConcurrent).by((c) => limitChecks(c.section["max-concurrent"])),
]);
