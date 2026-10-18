import { hocon } from "@o3co/ts.hocon/zod";
import { z } from "zod";

/** The units a duration key is read in. */
export type DurationUnit = "ms" | "s" | "m" | "h" | "d";
/** The units a size key is read in. */
export type SizeUnit = "B" | "KB" | "KiB" | "MB" | "MiB" | "GB" | "GiB";

/** A key that must name its unit; a bare number would read in a unit the operator did not choose. */
const named = { requireUnit: true } as const;

/** What the operator writes: a string, which JSON Schema can tell where the marker it feeds cannot. */
const written = (example: string, marker: z.ZodType<number, unknown>) =>
	// The marker reads any input, a string among them.
	z
		.string({ error: `written with its unit, such as ${example}` })
		.pipe(marker as z.ZodType<number, string>);

/**
 * Schemas for a section's keys of time and size, as HOCON writes them (`30s`, `500ms`, `64KiB`),
 * read as a number of the key's unit. Pipe one into a number schema for its bounds.
 */
export const setting = Object.freeze({
	duration: (unit: DurationUnit): z.ZodType<number, string> =>
		written("30s", hocon.duration(unit, named)),
	size: (unit: SizeUnit = "B"): z.ZodType<number, string> =>
		written("64KiB", hocon.bytes(unit, named)),
});
