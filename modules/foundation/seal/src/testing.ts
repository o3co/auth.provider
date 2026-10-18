import { randomBytes } from "node:crypto";
import type { z } from "zod";
import type { section } from "./section.ts";

export type SealSettings = z.input<typeof section>;

const testKey = randomBytes(32).toString("base64");

export function sealConfig(settings: Partial<SealSettings> = {}) {
	return { seal: { current: { id: "test", key: testKey }, ...settings } };
}
