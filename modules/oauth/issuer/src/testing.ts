import type { z } from "zod";
import type { section } from "./section.ts";

export type IssuerSettings = z.input<typeof section>;

export function issuerConfig(settings: Partial<IssuerSettings> = {}) {
	return { issuer: { url: "https://issuer.example", ...settings } };
}
