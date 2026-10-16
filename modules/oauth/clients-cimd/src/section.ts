import { hostEntryOf } from "@mod/outbound";
import { z } from "zod";

const hostEntry = z
	.string()
	.refine(
		(entry) => hostEntryOf(entry)?.kind === "name",
		"a host name, with a leading . for the names under it",
	);
const count = (min: number, max: number, fallback: number) =>
	z.number().int().min(min).max(max).default(fallback);

export const section = z.strictObject({
	allow: z.array(hostEntry).default([]),
	deny: z.array(hostEntry).default([]),
	scopes: z.array(z.string()).default([]),
	audiences: z.array(z.string()).default([]),
	// Outbound's caps bound max-bytes and timeout-ms too: a narrower never widens them.
	"max-bytes": count(1, 16_777_216, 5120),
	"timeout-ms": count(1, 60_000, 5000),
	"cache-seconds": count(0, 86_400, 600),
	"cache-entries": count(1, 100_000, 256),
	"refused-seconds": count(0, 86_400, 60),
	"max-concurrent": count(1, 1024, 8),
});

export type Settings = z.output<typeof section>;
