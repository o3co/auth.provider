import { join } from "node:path";
import { dependencyRecordOf, recordOf, refusals } from "./check-outside.mjs";

export type { OutsideRecord, Recorded, Registries } from "./check-outside.mjs";

/**
 * A pnpm lockfile held to what was recorded of the packages outside the release: `recordOf` reads
 * one from where pnpm installed it, `dependencyRecordOf` a dependency of one there, `refusals`
 * checks an app's lockfile, and `script` is the file an app runs to check its own: the same code,
 * bundled with what it uses, so it loads nothing of the install it checks.
 */
export const outsideLock = {
	recordOf,
	dependencyRecordOf,
	refusals,
	script: join(import.meta.dirname, "check-outside.bundled.mjs"),
} as const;
