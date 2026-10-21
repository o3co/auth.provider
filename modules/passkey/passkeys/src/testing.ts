import type { z } from "zod";
import type { section } from "./section.ts";

export type PasskeysSettings = z.input<typeof section>;

/** The passkeys part of a test's configuration: the section's defaults, but for what is given. */
export function passkeysConfig(settings: Partial<PasskeysSettings> = {}) {
	return { passkeys: { ...settings } };
}
