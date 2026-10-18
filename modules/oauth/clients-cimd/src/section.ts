import { setting } from "@mod/kernel";
import { hostEntryOf } from "@mod/outbound";
import { z } from "zod";

const hostEntry = z
	.string()
	.refine(
		(entry) => hostEntryOf(entry)?.kind === "name",
		"a host name, with a leading . for the names under it",
	);
const count = (min: number, max: number) => z.number().int().min(min).max(max);

export const section = z.strictObject({
	allow: z.array(hostEntry).prefault([]),
	deny: z.array(hostEntry).prefault([]),
	scopes: z.array(z.string()).prefault([]),
	audiences: z.array(z.string()).prefault([]),
	// Outbound's caps bound max-size and timeout too: a narrower never widens them.
	"max-size": setting
		.size("B")
		.pipe(count(1, 16_777_216))
		.prefault("5KiB")
		.describe("The largest document fetched: a size with a unit, e.g. 5KiB."),
	timeout: setting
		.duration("ms")
		.pipe(count(1, 60_000))
		.prefault("5s")
		.describe("How long a fetch may take: a duration with a unit, e.g. 5s."),
	"cache-lifetime": setting
		.duration("s")
		.pipe(count(0, 86_400))
		.prefault("10m")
		.describe("How long a document is kept: a duration with a unit, e.g. 10m."),
	"cache-entries": count(1, 100_000).prefault(256),
	"refused-lifetime": setting
		.duration("s")
		.pipe(count(0, 86_400))
		.prefault("1m")
		.describe("How long a refusal is remembered: a duration with a unit, e.g. 1m."),
	"max-concurrent": count(1, 1024).prefault(8),
});

export type Settings = z.output<typeof section>;
