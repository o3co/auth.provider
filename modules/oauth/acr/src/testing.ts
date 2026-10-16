import type { z } from "zod";
import type { section } from "./section.ts";

export function acrConfig(values: z.input<typeof section>["values"] = {}) {
	return { acr: { values } };
}
