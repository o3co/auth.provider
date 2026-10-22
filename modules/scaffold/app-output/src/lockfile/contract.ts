import { join } from "node:path";
import { recordOf, refusals } from "./check-outside.mjs";

export type { OutsideRecord, Recorded, Registries } from "./check-outside.mjs";

/**
 * A pnpm lockfile held to what was recorded of the packages outside the release: `recordOf` reads
 * one from where pnpm installed it, `refusals` checks an app's lockfile, and `script` is the file
 * an app runs to check its own, the same code.
 */
export const outsideLock = {
	recordOf,
	refusals,
	script: join(import.meta.dirname, "check-outside.mjs"),
} as const;
