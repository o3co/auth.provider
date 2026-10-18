import { hocon } from "@o3co/ts.hocon/zod";
import type { z } from "zod";

/** The units a duration key is read in. */
export type DurationUnit = "ms" | "s" | "m" | "h" | "d";
/** The units a size key is read in. */
export type SizeUnit = "B" | "KB" | "KiB" | "MB" | "MiB" | "GB" | "GiB";

/** A key that must name its unit; a bare number would read in a unit the operator did not choose. */
const named = { requireUnit: true } as const;

/**
 * Schemas for a section's keys of time and size, as HOCON writes them (`30s`, `500ms`, `64KiB`),
 * read as a number of the key's unit. Pipe one into a number schema for its bounds.
 */
export const setting = Object.freeze({
	duration: (unit: DurationUnit): z.ZodType<number, unknown> => hocon.duration(unit, named),
	size: (unit: SizeUnit = "B"): z.ZodType<number, unknown> => hocon.bytes(unit, named),
});
